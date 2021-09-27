import json
import os
from glob import glob
import subprocess
import logging
import asyncio

ALLOWLIST_REPOS = []

class AuthError(Exception):
    def __init__(self, value):
        self.value = value
 
    def __str__(self):
        return(repr(self.value))

class VulnReport():
    def _getVulnID(self, vuln)->str:
        '''returns the CVE ids'''
        try:
            cveid = vuln['identifiers']['CVE']
            cveid = ','.join(cveid)
            return cveid
        except KeyError:
            try:
                id = vuln['id']
                return id
            except KeyError:
                return 'UNKNOWN'
        
    def __init__(self, vuln: dict):
        self._vuln = vuln
        # name
        try:
            self.package_name = vuln['packageName']
        except KeyError:
            try:
                self.package_name = vuln['moduleName']
            except KeyError:
                self.package_name = 'UKNOWN'
        # version
        try:
            self.version = vuln['version']
        except KeyError:
            self.version = 'UNKNOWN'
        # vuln id
        self.vuln_string = self._getVulnID(vuln)
    
    def __eq__(self, other):
        if isinstance(other, VulnReport):
            return self.__key() == other.__key()
        return NotImplemented

    def __key(self):
        s_ids = self.vuln_string.split(',')
        s_ids.sort()
        v_sorted = ','.join(s_ids)
        return (self.package_name, self.version, v_sorted)
    
    def __hash__(self) -> int:
        return hash(self.__key())

    def __str__(self):
        return f'{self.package_name}-{self.version}: {self.vuln_string}'
    def __repr__(self) -> str:
        return self.__str__()

def addLoggingLevel(levelName, levelNum, methodName=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present 

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
       raise AttributeError('{} already defined in logging module'.format(levelName))
    if hasattr(logging, methodName):
       raise AttributeError('{} already defined in logging module'.format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
       raise AttributeError('{} already defined in logger class'.format(methodName))
    
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)
    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)

def _confLogger(level=logging.INFO-1):
    logger = logging.getLogger()
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    # ::notice file={name},line={line},endLine={endLine},title={title}::{message}
    # NOTE: no {endline} or {title} available by default
    formatter = logging.Formatter('::%(levelname)s file=%(filename)s,line=%(lineno)d::%(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    # add notice handler
    addLoggingLevel('notice', logging.INFO+1)

def _setOutput(name:str, value:str):
    #echo "::set-output name=action_fruit::strawberry"
    print(f'::set-output name={name}::{value}')

def _gemfile_from_gems(gems, project, platform):
    gemfile = ''
    gemfile += '''source ENV['GEM_SOURCE'] || "https://rubygems.org"\n'''
    for k,v in gems.items():
        if len(v) > 1:
            print(f"====DOUBLE VERSION ERROR====\nProject: {project}\nPlatform: {platform}\n====")
        gemfile += f'gem "{k}", "{v[0]}"\n'
    return gemfile

def _get_v_and_name(name_and_version):
    split = name_and_version.split('-')
    for s in split:
        try:
            [int(i) for i in s.split('.')]
            index = name_and_version.index(s)
            return s, name_and_version[:index-1]
        except ValueError:
            continue
    return None, ''

def build_gemfile(inspect_out: dict, project: str, platform: str):
    gems = {}
    no_url = set()
    for component in inspect_out:
        if 'url' not in component:
            no_url.add(component['name'])
            continue
        if component['url'].startswith('https://rubygems.org') or component['url'].startswith('http://rubygems.org'):
            if not component['url'].endswith('.gem'):
                logging.warning(f"Component starts with rubygems url but doesn't apear to be a gem. URL: {component['url']}")
                continue
            name_and_version = component['url'].split('/')[-1].replace('.gem','')
            version, name = _get_v_and_name(name_and_version)
            if name in gems:
                if not version in gems[name]:
                    gems[name].append(version)
            else:
                gems[name] = [version]
    # don't build an empty gemfile
    if len(gems) == 0:
        # print(inspect_out)
        return None, no_url
    else:
        gemfile = _gemfile_from_gems(gems, project, platform)
        return gemfile, no_url

def check_non_pl_repos(inspect_out: dict):
    warning_repos = set()
    no_url = set()
    for component in inspect_out:
        if 'url' not in component:
            no_url.add(component['name'])
            continue
        url = component['url']
        if url.endswith('.git'):
            if 'github.com/puppetlabs' not in url and url not in ALLOWLIST_REPOS:
                warning_repos.add(url)
    return warning_repos, no_url

def build_lockfile(gemfile_path, proj, plat):
    cdir = os.getcwd()
    os.chdir(gemfile_path)
    if os.path.exists("./Gemfile"):
        try:
            out = subprocess.call(['bundle', 'lock'])
            if out != 0:
                logging.warning(f"Couldn't generate lockfile for {proj} {plat}")
        except:
            logging.error(f'Error calling gemfile lock on {proj} {plat}')
    os.chdir(cdir)

def auth_snyk(s_token: str):
    # auth snyk
    auth_result = subprocess.call(['/usr/local/bin/snyk', 'auth', s_token])
    if auth_result != 0:
        logging.error(f"Error authenticating to snyk. Return code: {auth_result}")
        raise AuthError("error authenticating")

def run_snyk(path: str, project: str, platform: str, s_org: str, min_sev:str ='medium', no_monitor=False):
    cdir = os.getcwd()
    if os.path.isfile(path):
        os.chdir(os.path.dirname(path))
    else:
        os.chdir(path)
    try:
        # run snyk test
        if min_sev not in ['low','medium','high','critical']:
            raise ValueError("invalid severity level")
        sevstring = f'--severity-threshold={min_sev}'
        test_res = subprocess.run(['/usr/local/bin/snyk', 'test', sevstring, '--json'], stdout=subprocess.PIPE, check=False).stdout
        test_res = test_res.decode('utf-8')
        test_res = json.loads(test_res)
        # run snyk monitor
        if not no_monitor:
            snyk_org = f'--org={s_org}'
            snyk_proj = f'--project-name={project}_{platform}'
            monitor_res = subprocess.call(['/usr/local/bin/snyk', 'monitor', snyk_org, snyk_proj])
            if monitor_res != 0:
                logging.error(f'Error running snyk monitor for {project} {platform}')
        return test_res
    finally:
        os.chdir(cdir)

async def handle_proj_platform(project, platform):
    try:    
        sout = subprocess.check_output(['vanagon', 'inspect', project, platform], stderr=subprocess.DEVNULL).decode('utf-8')
        #print(sout)
        logging.debug(f'{project} {platform}')
        sout = json.loads(sout)
        gemfile, i_no_url = build_gemfile(sout, project, platform)
        components_no_url = set.union(components_no_url, i_no_url)
        i_warning_repos, i_no_url = check_non_pl_repos(sout)
        components_no_url = set.union(components_no_url, i_no_url)
        warning_repos = set.union(warning_repos, i_warning_repos)
        if gemfile:
            # build the gemfile and gemfile.lock
            foldername = os.path.join(gen_gemfiles, f'{project}_{platform}')
            if not os.path.exists(foldername):
                os.makedirs(foldername)
            with open(os.path.join(foldername, 'Gemfile'), 'w') as f:
                f.write(gemfile)
            build_lockfile(foldername, project, platform)
            # run snyk on it
            try:
                test_results = run_snyk(foldername, project, platform, s_org, no_monitor=no_monitor)
            except AuthError:
                return
            except ValueError:
                logging.error(f"invalid snyk severity on {project} {platform}")
                return
            try:
                for lic, _v in test_results['licensesPolicy']['orgLicenseRules'].items():
                    licenses_errors.add(lic)
            except KeyError:
                logging.error(f"Error parsing licenses for {project} {platform}")
                return
            try:
                for vuln in test_results['vulnerabilities']:
                    vulns.add(VulnReport(vuln))
            except KeyError:
                logging.error(f"Error parsing vulns for {project} {platform}")
                return
    except subprocess.CalledProcessError:
        return
    except Exception as e:
        logging.error(f'error on {project}_{platform}. Error: {e}')


async def main():
    # configure the logger
    _confLogger()
    # get variables from the env vars
    s_token = os.getenv("INPUT_SNYKTOKEN")
    if not s_token:
        raise ValueError("no snyk token")
    no_monitor = os.getenv('INPUT_NOMONITOR')
    if not no_monitor:
        no_monitor=False
    else:
        no_monitor=True
    s_org = os.getenv("INPUT_SNYKORG")
    if not s_org and not no_monitor:
        raise ValueError("no snyk org")
    skip_projects = os.getenv("INPUT_SKIPPROJECTS")
    if skip_projects:
        skip_projects = [p.strip() for p in skip_projects.split(',')]
    workdir = os.getenv("GITHUB_WORKSPACE")
    if not workdir:
        raise ValueError("no github workspace!")
    os.chdir(workdir)
    #os.chdir('/Users/jeremy.mill/Documents/forks/puppet-runtime')
    # auth snyk
    try:
        auth_snyk(s_token)
    except AuthError as e:
        logging.error("Couldn't authenticate snyk")
        raise e
    

    # build projects, targets, and output files
    gen_gemfiles = 'gen_gemfiles'
    if not os.path.exists(gen_gemfiles):
        os.makedirs(gen_gemfiles)
    projects = [y for x in os.walk('./configs/projects') for y in glob(os.path.join(x[0], '[a-zA-Z]*.rb'))]
    projects = [os.path.basename(p).replace('.rb','' ) for p in projects]
    if skip_projects:
        for p in skip_projects:
            if p in projects:
                projects.remove(p)
    platforms = [y for x in os.walk('./configs/platforms') for y in glob(os.path.join(x[0], '[a-zA-Z]*.rb'))]
    platforms = [os.path.basename(p).replace('.rb','' ) for p in platforms]

    # configure bundler
    subprocess.call(['bundle', 'config', 'specific_platform', 'true'])
    # run process
    components_no_url = set()
    warning_repos = set()
    licenses_errors = set()
    vulns = set()
    # tasks = [
    #     asyncio.ensure_future(safe_download(i))  # creating task starts coroutine
    #     for i
    #     in range(9)
    # ]
    tasks = []
    await asyncio.gather(*tasks)
    for project in projects:
        for platform in platforms:
            asyncio.ensure_future(handle_proj_platform(project, platform))
    #print('components without URLs:\n', components_no_url)
    if warning_repos:
        _setOutput('warning_repos', ','.join(warning_repos))
    else:
        _setOutput('warning_repos', '')
    if vulns:
        _setOutput('vulns', vulns)
    else:
        _setOutput('vulns', '')
    logging.notice('finished run')

if __name__ ==  '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
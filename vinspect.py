import json
import os
from glob import glob
import subprocess
import logging

ALLOWLIST_REPOS = []

class AuthError(Exception):
    def __init__(self, value):
        self.value = value
 
    def __str__(self):
        return(repr(self.value))

def _confLogger(level=logging.INFO):
    # add the notice level
    NOTICE_LEVEL_NUM = logging.INFO+1
    logging.addLevelName(NOTICE_LEVEL_NUM, "NOTICE")
    def notice(self, message, *args, **kws):
        if self.isEnabledFor(NOTICE_LEVEL_NUM):
            # Yes, logger takes its '*args' as 'args'.
            self._log(NOTICE_LEVEL_NUM, message, args, **kws)
    logging.Logger.notice = notice
    # configure the streamhandler
    logger = logging.getLogger()
    ch = logging.StreamHandler()
    ch.setLevel(level)
    # ::notice file={name},line={line},endLine={endLine},title={title}::{message}
    # NOTE: no {endline} or {title} available by default
    formatter = logging.Formatter('::%(levelname)s file=%(filename)s,line=%(lineno)d::%(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

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

def run_snyk(path: str, project: str, platform: str, s_token: str, s_org: str, min_sev:str ='medium'):
    cdir = os.getcwd()
    if os.path.isfile(path):
        os.chdir(os.path.dirname(path))
    else:
        os.chdir(path)
    try:
        # auth snyk
        auth_result = subprocess.call(['snyk', 'auth', s_token])
        if auth_result != 0:
            logging.error(f"Error authenticating to snyk. Return code: {auth_result}")
            raise AuthError("error authenticating")
        # run snyk test
        if min_sev not in ['low','medium','high','critical']:
            raise ValueError("invalid severity level")
        sevstring = f'--severity-threshold={min_sev}'
        test_res = subprocess.check_output(['snyk', 'test', sevstring, '--json']).decode('utf-8')
        test_res = json.loads(test_res)
        # run snyk monitor
        snyk_org = f'--org={s_org}'
        snyk_proj = f'--project-name={project}_{platform}'
        monitor_res = subprocess.call(['snyk', 'monitor', snyk_org, snyk_proj])
        if monitor_res != 0:
            logging.error(f'Error running snyk monitor for {project} {platform}')
        return test_res
    finally:
        os.chdir(cdir)

# # temp
# os.chdir('/Users/jeremy.mill/Documents/puppet-runtime')

if __name__ == "__main__":
    # configure the logger
    _confLogger()
    # get variables from the env vars
    s_token = os.getenv("SNYK_TOKEN")
    if not s_token:
        raise ValueError("no snyk token")
    s_org = os.getenv("SNYK_ORG")
    if not s_org:
        raise ValueError("no snyk org")
    

    # build projects, targets, and output files
    gen_gemfiles = 'gen_gemfiles'
    if not os.path.exists(gen_gemfiles):
        os.makedirs(gen_gemfiles)
    projects = [y for x in os.walk('./configs/projects') for y in glob(os.path.join(x[0], '[a-zA-Z]*.rb'))]
    projects = [os.path.basename(p).replace('.rb','' ) for p in projects]
    platforms = [y for x in os.walk('./configs/platforms') for y in glob(os.path.join(x[0], '[a-zA-Z]*.rb'))]
    platforms = [os.path.basename(p).replace('.rb','' ) for p in platforms]

    # configure bundler
    subprocess.call(['bundle', 'config', 'specific_platform', 'true'])
    # run process
    components_no_url = set()
    warning_repos = set()
    for project in projects:
        for platform in platforms:
            try:
                sout = subprocess.check_output(['vanagon', 'inspect', project, platform], stderr=subprocess.DEVNULL).decode('utf-8')
                #print(sout)
                print(f'{project} {platform}')
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
                        test_results = run_snyk(foldername, project, platform, s_token, s_org)
                    except AuthError:
                        continue
                    except ValueError:
                        logging.error(f"invalid snyk severity on {project} {platform}")
                        continue
            except subprocess.CalledProcessError:
                continue
            except Exception as e:
                print(f'error on {project}_{platform}')
                print(e)
                raise e
    print('components without URLs:\n', components_no_url)
    if warning_repos:
        print('Warning Repos: ', warning_repos)
    print('done')
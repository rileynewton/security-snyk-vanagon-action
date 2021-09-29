# security-snyk-vanagon-action

This action runs snyk on generated gemfiles for vanagon builds. 

### What this will identify
This tool will use the output of `vanagon inspect` in order to identify any gems pulled in from `rubygems.org`. It builds a pseudo Gemfile for each project and platform in the `configs` directory of a vanagon repository. It then creates a Gemfile.lock from the pseudo Gemfile and scans it with snyk.

## Inputs

### snykToken (required)
This input is the secret snyk token

### snykOrg (required)
The organization in snyk to send results to

### noMonitor (not required)
If you just want to run `snyk test` and not `snyk monitor` you should set this input to `true`

### skipProjects
A comma separated list of projects to skip

### skipPlatforms
A comma separated list of platforms to skip

## Outputs
### vulns
An array of vulnerable packages

### warning_repos
Array of non-puppet non-trusted (non-puppet) repos in use

## Example usage
plasee see `sample_workflow.yaml` for a sample

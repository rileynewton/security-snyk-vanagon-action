# security-snyk-vanagon-action

This action runs snyk on generated gemfiles for vanagon builds

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
plasee see `action.yml` for a sample

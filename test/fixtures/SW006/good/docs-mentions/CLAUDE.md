# Environment

Put variables in the `env` section of settings.
Check one variable with `printenv HOME` or `env | grep -q CI`.
Run tools with `env NODE_ENV=test npm test`.

```python
env = dict(os.environ)
subprocess.run(cmd, env=env)
```

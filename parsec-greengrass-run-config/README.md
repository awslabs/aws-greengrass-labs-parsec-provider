Create a file called `secrets.env` in this directory
Add the following secrets to it:
```
AWS_ACCESS_KEY_ID=AK...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=eu-central-1
```

Call the script to init the run configuration
```shell
init.sh
```

Make sure that IntelliJ has a JDK called `corretto-8` you can download it directly from IntelliJ and name
it `corretto-8`, the generated run configs will depend on it.

In IntelliJ you should find two new run configurations:
- GreenGrassProvision
- GreenGrassRun

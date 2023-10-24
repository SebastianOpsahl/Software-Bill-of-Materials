Use this line to run the code 
```
python sbom.py test_repos
```

I have implemented all the tasks plus the optional features.

***Ideas for feautures for further expansion***
Given the current software which based on given repository retrieves the dependencies and write it to the user with information such as:
- Dependency name
- Version
- Type
- File path
- Git commit hash

One idea I have in mind is dependency vulnerability check. This feature would involve checking the dependencies up to vulnerability databases such as National Vulnerability Database. This feature would automatically check if any of the listed dependencies have known vulnerabilities. This is important for security and knowing vulnerabilities that may come from the dependencies they use. Which can be useful when deciding for dependencies and when for securing weaknesses dependencies.

Another idea I have in mind is being able to based on the dependencies the repository have, return similar dependencies (dependencies that aim to do the same task). For example, if the user plan to change or want to know about other options.

Another idea I have in mind is dependency update notification which would automatically check if there re newer versions available for the listed dependencies. This would be especially useful for ensuring that dependencies are kept up-to-date.
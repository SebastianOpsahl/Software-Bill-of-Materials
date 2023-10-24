import os, json, csv, sys, subprocess

def get_all_subdirectories(path):
    # returns a list of all subdirectories in the given path using os.listdir(path) to return a list of all files and 
    # directories in the given path, and then checks if the given item is a directory
    return [os.path.join(path, d) for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]

# for each subdirectory, check if it contains either a requirements.txt or a package.json file, if it constains it
# returns the dependency file present in the subdirectory
def get_dependency_files(subdirectory):
    # adds the given directory to the file name
    req_file = os.path.join(subdirectory, "requirements.txt")
    pkg_file = os.path.join(subdirectory, "package.json")

    if os.path.exists(req_file):
        return req_file
    elif os.path.exists(pkg_file):
        return pkg_file
    else:
        return None

# parse_requirements and parse_package_json, based on the type of file found (requirements.txt or package.json), parse the content to get the list of dependencies

# parses a requirements.txt file and return a list of it's dependencies
def parse_requirements(file_path):
    # opens file in read mode
    with open(file_path, 'r') as file:
        # stores all the lines in the list variable
        lines = file.readlines()
    
    # list to store dependencies
    dependencies = []
    for line in lines:
        # remove whitespaces and split on '==', assuming that dependencies uses '==' to attach value 
        parts = line.strip().split('==')
        # if content doesn't have both sites (name and version) continue
        if len(parts) != 2:
            print(f"Incorrect format detected in {file_path} for line: {line.strip()}")
            continue
        # extract and add it to the dependicies
        name, version = parts
        dependencies.append({'name': name, 'version': version, 'type': 'pip'})
    return dependencies

# parses a package.json file and return a list of it's dependencies
def parse_package_json(file_path):
    # list to store dependencies
    dependencies = []

    # opens file in read mode
    with open(file_path, 'r') as file:
        # extracts the content and checks if it is empty before reading
        content = file.read()
        # if empty or just white space return empty
        if not content.strip():  
            return dependencies
        
        data = json.loads(content)
    
    # if has 'dependencies' key iterate over it, if not empty list
    for name, version in data.get('dependencies', {}).items():
        # appends name, version and type of dependency
        dependencies.append({'name': name, 'version': version, 'type': 'npm'})
    return dependencies

# parses a package-lock.json file and return a list of it's dependencies, both direct and indirect
def parse_package_lock_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    # recursive function to extract dependencies from package-lock.json 
    def extract_deps(node):
        dependencies = []
        # if has 'dependencies' key iterate over it, if not empty list
        for name, attributes in node.get('dependencies', {}).items():
            version = attributes.get('version', '')
            dependencies.append({'name': name, 'version': version, 'type': 'npm'})
            dependencies.extend(extract_deps(attributes))
        return dependencies

    return extract_deps(data)

# extracts dependency data from a given repository path
def extract_data_from_repository(repo_path):    
    # gets the dependency file based on the repository path
    dependency_file = get_dependency_files(repo_path)
    
    # if no dependencies files are found return empty list
    if not dependency_file:
        return []
    
    # empty list to place the dependencies in 
    dependencies = []

    #retrieves the latest git commit hash
    commit_hash = get_latest_git_commit(repo_path)

    # checks if it is python type file or json
    if dependency_file.endswith("requirements.txt"):
        dependencies = parse_requirements(dependency_file)
    elif dependency_file.endswith("package.json"):
        # if json check if package-lock.json, because this would keep both direct and indirect dependencies so extract from it
        package_lock_file = os.path.join(os.path.dirname(dependency_file), "package-lock.json")
        if os.path.exists(package_lock_file):
            dependencies = parse_package_lock_json(package_lock_file)
        else:
            # if not package-lock.json use the package.json to retrieve from
            dependencies = parse_package_json(dependency_file)
    
    # adds each dependency's filepath and latest commit hash
    for dep in dependencies:
        dep['file_path'] = dependency_file
        dep['git_commit'] = commit_hash
    
    return dependencies

# with the extracted data create and save 'sbom.csv' and 'sbom.json' in the main directory
def save_to_csv(data, output_path):
    # opens it with writing premissions, if file aldready exists it gets overwritten if such file
    # doesn't already exist it get overwritten
    with open(output_path, 'w', newline='') as file:
        # sets headers for the data
        writer = csv.DictWriter(file, fieldnames=["name", "version", "type", "file_path", "git_commit"])
        writer.writeheader()
        # applies the data
        for row in data:
            writer.writerow(row)

# saves the extracted data to a JSON file
def save_to_json(data, output_path):
    # opens file with writing premissions 
    # indent makes it more readable by creating new lines with indent 
    with open(output_path, 'w') as file:
        json.dump(data, file, indent=4)

# gets the latest git commit hash from given repository
def get_latest_git_commit(repo_path):
    # cmd is the shell command we want to run, log shows us the log and we narrow it done to the commit hash
    # with --format=%H and narrow it down to the latest with "-n", "1"
    cmd = ["git", "-C", repo_path, "log", "--format=%H", "-n", "1"]
    
    try:
        # tries to retrieve the hash, use universal_newlines=True to get it in string and strip() it from whitespaces
        commit_hash = subprocess.check_output(cmd, universal_newlines=True).strip()
        return commit_hash
    # specific error handling
    except subprocess.CalledProcessError:
        print(f"Failed to retrieve git commit for {repo_path}. The repository might not have any commits or isn't a valid git repository.")
        return None
    # general error handling
    except Exception as e:
        print(f"An error occurred while trying to retrieve the git commit for {repo_path}. Error: {e}")
        return None

# generates a Software Bill of Materials for the provided directory
def generate_sbom(main_directory):
    # retireves all subdirectories in the main directory
    repositories = get_all_subdirectories(main_directory)
    
    # list to store all extracted dependencies 
    all_dependencies = []
    
    # for each repository/subdirectory extract its dependency data
    for repo in repositories:
        repo_data = extract_data_from_repository(repo)
        # adds it to the dependencies list
        all_dependencies.extend(repo_data)

    if not all_dependencies:
        print("The directory contained no dependencies.")
        # exits the program
        sys.exit(1)
    
    # defines the paths for the output files
    csv_output_path = os.path.join(main_directory, "sbom.csv")
    json_output_path = os.path.join(main_directory, "sbom.json")
    
    # save the extracted data to the files
    save_to_csv(all_dependencies, csv_output_path)
    save_to_json(all_dependencies, json_output_path)
    
    # summary prints
    print(f"Found {len(repositories)} repositories in '{main_directory}'")
    print(f"Saved SBOM in CSV format to '{csv_output_path}'")
    print(f"Saved SBOM in JSON format to '{json_output_path}'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        # helpful error prints
        print("Error: Incorrect number of arguments.")
        print("Usage: python3 sbom.py <directory_path>")
        sys.exit(1)

    main_directory = sys.argv[1]
    # check if the directory exists, to provide helpful erorr code if it doesn't
    if not os.path.isdir(main_directory):
        print(f"Error: The provided path '{main_directory}' is not a valid directory.")
        sys.exit(2)
    generate_sbom(main_directory)
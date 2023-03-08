import os
import re

# Path to the folder to search
working_dir = os.getcwd()
folder_path = os.path.join(working_dir, 'rules-dev/Security inventory/Windows')
include_folder = os.path.join(working_dir, 'rules-dev/Security inventory/Windows/Shared')
output_folder = os.path.join(working_dir, 'rules/Security inventory/Windows')

print("Current working dir: ", working_dir)
print("Using input: ", folder_path)
print("Using include: ", include_folder)
print("Using output: ", output_folder)

# Create the "transpiled" directory-structure if it doesn't exist
if not os.path.exists(output_folder):
    os.makedirs(output_folder)
    
# Clean old output
for dirpath, dirnames, filenames in os.walk(output_folder):
    for filename in filenames:
        file_path = os.path.join(dirpath, filename)
        # Überprüfen, ob es sich um eine Datei handelt
        if os.path.isfile(file_path):
            # Lösche die Datei
            os.remove(file_path)

# List of folders to exclude
exclude_folders = ['Shared']

# Loop through all files in the folder
for dirpath, dirnames, filenames in os.walk(folder_path):
    
    for filename in filenames:
        file_path = os.path.join(dirpath, filename)
        
        print("Processing: ", file_path )
    
        # Check if it's a .ps1 file and not in an excluded folder
        if filename.endswith('.ps1') and not any(exclude_folder in file_path for exclude_folder in exclude_folders):
            with open(file_path, 'r') as file:
                # Read the contents of the file
                content = file.read()
    
                # Search for includes
                includes = re.findall(r'(?<=Shared\\)[^\\]+\.ps1', content, flags=re.IGNORECASE)
                
                print("Found: ", len(includes), " includes")
    
                # Loop through all found includes
                for include in includes:
                    # Replace the include with the contents of the corresponding file
                    include_path = os.path.join(include_folder, include)
                    with open(include_path, 'r') as include_file:
                        include_content = include_file.read()
                        includes_ex = re.findall(r'.*(?<=Shared\\)' + re.escape(include) + r'.*', content, flags=re.IGNORECASE)
                        
                        if len(includes_ex) > 0:
                            content = content.replace(includes_ex[0], include_content)
                            
                        content = re.sub(r'.*#Requires -Version.*(\r?\n)?', '', content, flags=re.IGNORECASE)
    
                # Extract subfolder name
                subfolder = os.path.relpath(os.path.dirname(file_path), folder_path)
                
                # Write the transpiled contents to a new file in the "transpiled" directory
                transpiled_path = os.path.join(output_folder, subfolder, filename)
                transpiled_path_dir = os.path.join(output_folder, subfolder)
                
                #create subfolders if missing
                if not os.path.exists(transpiled_path_dir):
                    os.makedirs(transpiled_path_dir)
                    
                print("Writing file: ", transpiled_file)
                with open(transpiled_path, 'w') as transpiled_file:
                    transpiled_file.write(content)
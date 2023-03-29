import os
import re

try:
    # Path to the folder to search
    working_dir = os.getcwd()
except:
    print("Error: Could not get current working directory")

    # Exit the script
    exit()

file_read_me = os.path.join(working_dir, 'README.md')
badge_list = []

def add_custom_badge(tag, description, value, color):
    badge_list.append(f"![{tag}](https://img.shields.io/badge/{description}-{value}-{color})")

def add_license_badge():
    badge_list.append("![license](https://img.shields.io/github/license/vastlimits/uberAgent-config)")

def get_current_branch():
    try:
        github_ref = os.environ.get("GITHUB_REF", "")
        if github_ref.startswith("refs/heads/"):
            return github_ref[len("refs/heads/"):]
        return "unknown"
    except:
        return "unknown"

branch = get_current_branch()
print(f"Generating badge for branch: {branch}")

 # Handle exceptions when opening the file
try:
    # Open the file
    with open(file_read_me, 'r') as read_file:
        # Read the file
        file_content = read_file.read()
        read_file.close()

        pattern = r'\[comment\]: # \(BADGE_SECTION_START\)(.*?)\[comment\]: # \(BADGE_SECTION_END\)'
        match = re.search(pattern, file_content, flags=re.DOTALL)

        if match:
            result = match.group(1).strip()

            add_license_badge()
            add_custom_badge("branch", "branch", branch, "blue")

            # Update the file content with the new badge. Replace result with the new badge list. join the list and add spaces
            file_content = file_content.replace(result, " ".join(badge_list))

            # Write the file
            with open(file_read_me, 'w') as write_file:
                write_file.write(file_content)
                write_file.close()
        else:
            print("Error: Failed to find badge section")
except:
    print("Error: Could not read file")

    # Exit the script
    exit()

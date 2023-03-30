import os
import re
from urllib.parse import quote

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

    # Replace - with -- to avoid issues with the badge
    if "-" in value:
        value = value.replace("-", "--")

    try:
        url_parts = f"{description}-{value}-{color}"
        encoded_url = f"https://img.shields.io/badge/{quote(url_parts)}"
        badge_list.append(f"![{tag}]({encoded_url})")
    except:
        print(f"Error: Could not generate badge for {tag}")

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

            add_custom_badge("branch", "branch", branch, "blue")

            try: 
                TRANSPILER_SUCCSESS = os.environ.get("TRANSPILER_SUCCSESS", "")
                TRANSPILER_PROCESSED = os.environ.get("TRANSPILER_PROCESSED", "")
                TRANSPILER_FAILED = os.environ.get("TRANSPILER_FAILED", "")
                ANALYZER_ERRORS = os.environ.get("ANALYZER_ERRORS", "")
                ANALYZER_WARNINGS = os.environ.get("ANALYZER_WARNINGS", "")
                ANALYZER_NOTES = os.environ.get("ANALYZER_NOTES", "")

                print(f"Transpiler: {TRANSPILER_SUCCSESS} success, {TRANSPILER_PROCESSED} processed")
                print(f"Syntax check: {ANALYZER_ERRORS} errors, {ANALYZER_WARNINGS} warnings, {ANALYZER_NOTES} notes")

                transpilation_color = "green"
                if TRANSPILER_SUCCSESS != TRANSPILER_PROCESSED:
                    transpilation_color = "red"

                syntax_check_color = "green"
                if ANALYZER_ERRORS != "0":
                    syntax_check_color = "red"
                elif ANALYZER_WARNINGS != "0":
                    syntax_check_color = "yellow"

                add_custom_badge("msi transpilation", "transpilation", f"{TRANSPILER_SUCCSESS} success, {TRANSPILER_FAILED} failed, {TRANSPILER_PROCESSED} processed", transpilation_color)
                add_custom_badge("msi syntax check", "syntax check", f"{ANALYZER_ERRORS} errors, {ANALYZER_WARNINGS} warnings, {ANALYZER_NOTES} notes", syntax_check_color)

            except:
                print("Error: Failed to get environment variables")
                add_custom_badge("transpilation", "transpilation", "failed", "red")
                add_custom_badge("syntax check", "syntax check", "failed", "red")

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

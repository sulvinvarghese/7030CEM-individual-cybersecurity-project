import os
from pathlib import Path

def add_header_footer(txt_file, page_number):
    txt_file.write(f'\nPage {page_number}\n')
    txt_file.write('-' * 40 + '\n')

def add_chapter_title(txt_file, title):
    txt_file.write(title + '\n')
    txt_file.write('=' * len(title) + '\n\n')

def add_chapter_body(txt_file, body):
    txt_file.write(body + '\n\n')

def add_files_to_txt(txt_file, root_folder):
    valid_extensions = ['.dockerfile', '.yml', '.yaml', '.cnf', '.conf','.js', '.json', '.sh', '.cron']
    file_count = 0
    page_number = 1

    for root, _, files in os.walk(root_folder):
        print(f"Checking directory: {root}")
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in valid_extensions:
                print(f"Processing file: {file_path}")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_contents = f.read()
                    print(f"Read file successfully: {file_path}")
                except Exception as e:
                    file_contents = f"Error reading file: {e}"
                    print(f"Error reading file {file_path}: {e}")

                if file_contents.strip():  # Only add content if the content is not empty
                    relative_path = os.path.relpath(file_path, root_folder)
                    add_chapter_title(txt_file, f'File: {relative_path}')
                    add_chapter_body(txt_file, file_contents)
                    add_header_footer(txt_file, page_number)
                    file_count += 1
                    page_number += 1

    if file_count == 0:
        print("No valid files found.")
    else:
        print(f"Total files processed: {file_count}")

def main():
    current_directory = os.getcwd()

    print(f"Current working directory: {current_directory}")

    if not Path(current_directory).exists():
        print(f"Directory not found: {current_directory}")
        return

    print(f"Found directory: {current_directory}")
    output_txt = 'output.txt'
    
    with open(output_txt, 'w', encoding='utf-8') as txt_file:
        print(f"Starting to process the directory: {current_directory}")
        add_files_to_txt(txt_file, current_directory)

    print(f'Text file created successfully: {output_txt}')

if __name__ == "__main__":
    main()

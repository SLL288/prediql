#!/usr/bin/env python3
"""
Script to create a new folder in stable-results and move specific folders and files into it.
"""

import os
import shutil
from pathlib import Path

def main():
    # Get the current working directory (should be SinQL)
    current_dir = Path.cwd()
    stable_results_dir = current_dir / "stable-results"
    
    # Ensure stable-results directory exists
    if not stable_results_dir.exists():
        print("Error: stable-results directory not found!")
        return
    
    # Ask for folder name
    folder_name = input("Enter the name for the new folder: ").strip()
    
    if not folder_name:
        print("Error: Folder name cannot be empty!")
        return
    
    # Create the new folder path
    new_folder_path = stable_results_dir / folder_name
    
    # Check if folder already exists
    if new_folder_path.exists():
        print(f"Error: Folder '{folder_name}' already exists in stable-results!")
        return
    
    try:
        # Create the new folder
        new_folder_path.mkdir(parents=True, exist_ok=True)
        print(f"Created folder: {new_folder_path}")
        
        # Items to move
        items_to_move = [
            "prompts",
            "prediql-output",
            "generated_query_info.json",
            "introspection_result.json",
            "real_data.json"
        ]
        
        # Move folders and files
        moved_items = []
        for item in items_to_move:
            source_path = current_dir / item
            dest_path = new_folder_path / item
            
            if source_path.exists():
                if source_path.is_dir():
                    shutil.move(str(source_path), str(dest_path))
                    print(f"Moved folder: {item}")
                else:
                    shutil.move(str(source_path), str(dest_path))
                    print(f"Moved file: {item}")
                moved_items.append(item)
            else:
                print(f"Warning: {item} not found, skipping...")
        
        # Move .yml files from load_introspection directory
        load_introspection_dir = current_dir / "load_introspection"
        if load_introspection_dir.exists():
            yml_files = list(load_introspection_dir.glob("*.yml"))
            for yml_file in yml_files:
                dest_path = new_folder_path / yml_file.name
                shutil.move(str(yml_file), str(dest_path))
                print(f"Moved file: load_introspection/{yml_file.name}")
                moved_items.append(f"load_introspection/{yml_file.name}")
        
        print(f"\nSuccessfully moved {len(moved_items)} items to {new_folder_path}")
        print("Moved items:")
        for item in moved_items:
            print(f"  - {item}")
            
    except Exception as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__":
    main()

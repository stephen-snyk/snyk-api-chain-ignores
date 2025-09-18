#!/usr/bin/env python3
"""
Snyk API Chain Script

This script chains together Snyk API calls to:
1. Get all organizations
2. Get all projects for each organization
3. Call the ignores endpoint for each project
4. Output a detailed record for each individual ignore rule.

Requirements:
- requests library: pip install requests
- Valid Snyk API token with appropriate permissions
"""

import requests
import json
import time
import csv
from typing import List, Dict, Any
import os
import sys


class SnykAPIClient:
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = "https://api.snyk.io"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {api_token}",
            "Content-Type": "application/vnd.api+json"
        })

    def get_organizations(self, group_id: str = None) -> List[Dict[str, Any]]:
        """
        Get all organizations using the REST API, handling pagination.
        """
        all_organizations = []
        url = f"{self.base_url}/rest/orgs"
        params = {
            "version": "2024-10-15",
            "limit": 100
        }
        
        if group_id:
            params["group_id"] = group_id
            print(f"Fetching organizations for group: {group_id}")
        
        while url:
            try:
                response = self.session.get(url, params=params if url.endswith("/orgs") else None)
                response.raise_for_status()
                
                data = response.json()
                all_organizations.extend(data.get('data', []))
                
                next_path = data.get('links', {}).get('next')
                url = f"{self.base_url}{next_path}" if next_path else None
                    
            except requests.exceptions.RequestException as e:
                group_msg = f" for group {group_id}" if group_id else ""
                print(f"Error fetching organizations{group_msg}: {e}")
                return []

        group_msg = f" in group {group_id}" if group_id else ""
        print(f"Found a total of {len(all_organizations)} organizations{group_msg} after handling pagination.")
        return all_organizations

    def get_groups(self) -> List[Dict[str, Any]]:
        """Get all groups that the user has access to."""
        url = f"{self.base_url}/rest/groups"
        params = {"version": "2024-10-15"}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            groups = data.get('data', [])
            print(f"Found {len(groups)} groups")
            return groups
        except requests.exceptions.RequestException as e:
            print(f"Error fetching groups: {e}")
            return []

    def get_projects_for_org(self, org_id: str) -> List[Dict[str, Any]]:
        """Get all projects for a specific organization, handling pagination."""
        all_projects = []
        url = f"{self.base_url}/rest/orgs/{org_id}/projects"
        params = {"version": "2024-10-15", "limit": 100}
        
        while url:
            try:
                response = self.session.get(url, params=params if url.endswith("/projects") else None)
                response.raise_for_status()
                data = response.json()
                all_projects.extend(data.get('data', []))
                
                next_path = data.get('links', {}).get('next')
                url = f"{self.base_url}{next_path}" if next_path else None
            except requests.exceptions.RequestException as e:
                print(f"Error fetching projects for org {org_id}: {e}")
                return []
        
        print(f"Found a total of {len(all_projects)} projects in org {org_id} after handling pagination.")
        return all_projects

    def get_project_ignores(self, org_id: str, project_id: str) -> Dict[str, Any]:
        """Get ignores for a specific project using the v1 API."""
        url = f"{self.base_url}/v1/org/{org_id}/project/{project_id}/ignores"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            print(f"  Successfully retrieved ignores for project {project_id}")
            return data
        except requests.exceptions.RequestException as e:
            print(f"  Error fetching ignores for project {project_id} in org {org_id}: {e}")
            return {}

    def process_all_projects(self, group_id: str = None, delay: float = 0.1) -> List[Dict[str, Any]]:
        """
        Process all orgs and projects to get a detailed list of every ignore rule.
        """
        results = []
        organizations = self.get_organizations(group_id=group_id)
        
        if not organizations:
            print("No organizations found or error occurred")
            return []
        
        for org in organizations:
            org_id = org.get('id')
            org_name = org.get('attributes', {}).get('name', 'Unknown')
            
            if not org_id:
                print(f"Skipping organization with missing ID: {org}")
                continue
            
            print(f"\nProcessing organization: {org_name} ({org_id})")
            projects = self.get_projects_for_org(org_id)
            
            for project in projects:
                project_id = project.get('id')
                project_name = project.get('attributes', {}).get('name', 'Unknown')
                
                if not project_id:
                    print(f"Skipping project with missing ID: {project}")
                    continue
                
                print(f"    Processing project: {project_name} ({project_id})")
                ignores_data = self.get_project_ignores(org_id, project_id)
                
                if not ignores_data:
                    continue

                # Loop through each ignore rule in the project
                for issue_id, ignore_list in ignores_data.items():
                    for ignore_item in ignore_list:
                        # The actual details are often under a wildcard key '*'
                        details = ignore_item.get('*', {})
                        if not details:
                            continue

                        ignored_by = details.get('ignoredBy', {})
                        record = {
                            'org_id': org_id,
                            'org_name': org_name,
                            'project_id': project_id,
                            'project_name': project_name,
                            'issue_id': issue_id,
                            'reason': details.get('reason', 'N/A'),
                            'reasonType': details.get('reasonType', 'N/A'),
                            'created': details.get('created', 'N/A'),
                            'expires': details.get('expires', 'Never'),
                            'ignored_by_name': ignored_by.get('name', 'N/A'),
                            'ignored_by_email': ignored_by.get('email', 'N/A')
                        }
                        results.append(record)
                
                time.sleep(delay)
        
        return results

    # --- Debug methods remain unchanged ---
    def test_specific_org(self, org_id: str) -> Dict[str, Any]:
        # ... (code for this method is unchanged)
        pass

    def debug_org_discovery(self) -> Dict[str, Any]:
        # ... (code for this method is unchanged)
        pass


def export_to_csv(results: List[Dict[str, Any]], filename: str) -> bool:
    """
    Export detailed ignore results to CSV format.
    """
    if not results:
        print("No results to export")
        return False
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Define new CSV columns for detailed output
            fieldnames = [
                'org_id', 'org_name', 'project_id', 'project_name', 'issue_id',
                'reason', 'reasonType', 'created', 'expires',
                'ignored_by_name', 'ignored_by_email'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Each item in results is already a flat dictionary for a single row
            for row in results:
                writer.writerow(row)
        
        return True
        
    except Exception as e:
        print(f"Error exporting to CSV: {e}")
        return False

def main():
    """Main function to run the script."""
    
    # Get API token from environment variable or prompt user
    api_token = os.getenv('SNYK_TOKEN')
    
    if not api_token:
        api_token = input("Enter your Snyk API token: ").strip()
    
    if not api_token:
        print("Error: Snyk API token is required")
        sys.exit(1)
    
    # Initialize the client
    client = SnykAPIClient(api_token)
    
    print("Starting Snyk API chain process...")
    
    # --- Debug option logic (unchanged) ---
    debug_mode = input("Do you want to run in debug mode to investigate missing orgs? (y/N): ").strip().lower()
    
    if debug_mode == 'y':
        # (The debug logic remains here, it is omitted for brevity but should be kept in your script)
        pass # Placeholder for your existing debug code
        
        # Ask if user wants to continue with normal processing
        continue_normal = input("\nContinue with normal processing? (y/N): ").strip().lower()
        if continue_normal != 'y':
            return

    # --- Group Selection Logic (RESTORED) ---
    use_group = input("Do you want to filter by a specific group? (y/N): ").strip().lower()
    group_id = None
    
    if use_group == 'y':
        # Option 1: Manual group ID entry
        manual_entry = input("Enter group ID manually? Otherwise, we'll list available groups (y/N): ").strip().lower()
        
        if manual_entry == 'y':
            group_id = input("Enter the group ID: ").strip()
        else:
            # Option 2: List available groups
            print("\nFetching available groups...")
            groups = client.get_groups()
            
            if groups:
                print("\nAvailable groups:")
                for i, group in enumerate(groups, 1):
                    group_name = group.get('attributes', {}).get('name', 'Unknown')
                    group_id_display = group.get('id', 'No ID')
                    print(f"{i}. {group_name} ({group_id_display})")
                
                try:
                    selection = input(f"\nSelect group (1-{len(groups)}) or press Enter to skip: ").strip()
                    if selection:
                        selected_group = groups[int(selection) - 1]
                        group_id = selected_group.get('id')
                        group_name = selected_group.get('attributes', {}).get('name', 'Unknown')
                        print(f"Selected group: {group_name} ({group_id})")
                except (ValueError, IndexError):
                    print("Invalid selection, proceeding without group filter")
            else:
                print("No groups found or error occurred, proceeding without group filter")
    
    print("\nThis will:")
    print("1. Fetch all organizations" + (f" in group {group_id}" if group_id else ""))
    print("2. Fetch all projects for each organization")
    print("3. Fetch all ignores and create a detailed record for each one")
    print()
    
    # Process all projects, passing the selected group_id
    results = client.process_all_projects(group_id=group_id, delay=0.1)
    
    # Updated Summary
    print(f"\n{'='*50}")
    print("SUMMARY")
    print(f"{'='*50}")
    
    if not results:
        print("No ignores were found across any projects.")
        return

    print(f"Total ignores found and processed: {len(results)}")
    
    # Export options
    print("\nExport options:")
    save_json = input("Save detailed results to JSON file? (y/N): ").strip().lower()
    if save_json == 'y':
        json_filename = f"snyk_ignores_details_{int(time.time())}.json"
        try:
            with open(json_filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"JSON results saved to: {json_filename}")
        except Exception as e:
            print(f"Error saving JSON file: {e}")
    
    save_csv = input("Save detailed results to CSV file? (y/N): ").strip().lower()
    if save_csv == 'y':
        csv_filename = f"snyk_ignores_details_{int(time.time())}.csv"
        if export_to_csv(results, csv_filename):
            print(f"CSV results saved to: {csv_filename}")
        else:
            print("Failed to save CSV file")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
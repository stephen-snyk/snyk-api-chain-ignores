#!/usr/bin/env python3
"""
Snyk API Chain Script

This script chains together Snyk API calls to:
1. Get all organizations
2. Get all projects for each organization
3. Call the ignores endpoint for each project

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
        
        Args:
            group_id: Optional group ID to filter organizations
            
        Returns:
            List of organization data
        """
        all_organizations = []
        url = f"{self.base_url}/rest/orgs"
        params = {
            "version": "2024-10-15",
            "limit": 100  # Set the limit to 100 per page
        }
        
        # Add group_id parameter if provided
        if group_id:
            params["group_id"] = group_id
            print(f"Fetching organizations for group: {group_id}")
        
        while url:
            try:
                # Params are only needed for the first request, subsequent requests use the full 'next' URL
                response = self.session.get(url, params=params if url.endswith("/orgs") else None)
                response.raise_for_status()
                
                data = response.json()
                all_organizations.extend(data.get('data', []))
                
                # Check for the next pagination link
                next_path = data.get('links', {}).get('next')
                if next_path:
                    url = f"{self.base_url}{next_path}"
                else:
                    url = None # End the loop
                    
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
        params = {
            "version": "2024-10-15"
        }
        
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
        params = {
            "version": "2024-10-15",
            "limit": 100 # Set the limit to 100 per page
        }
        
        while url:
            try:
                # Params are only needed for the first request
                response = self.session.get(url, params=params if url.endswith("/projects") else None)
                response.raise_for_status()
                
                data = response.json()
                all_projects.extend(data.get('data', []))
                
                # Check for the next pagination link
                next_path = data.get('links', {}).get('next')
                if next_path:
                    url = f"{self.base_url}{next_path}"
                else:
                    url = None # End the loop

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

    # --- The rest of the methods (process_all_projects, test_specific_org, etc.) remain unchanged ---
    # (You can copy the methods below this line from the previous corrected script if needed)
    
    def process_all_projects(self, group_id: str = None, delay: float = 0.1) -> List[Dict[str, Any]]:
        """
        Process all organizations and projects to get ignores data.
        
        Args:
            group_id: Optional group ID to filter organizations
            delay: Delay between API calls to avoid rate limiting
            
        Returns:
            List of results with org_id, project_id, and ignores data
        """
        results = []
        
        # Step 1: Get all organizations (optionally filtered by group)
        organizations = self.get_organizations(group_id=group_id)
        
        if not organizations:
            print("No organizations found or error occurred")
            return [] # Return empty list if no orgs
        
        # Step 2: Process each organization
        for org in organizations:
            org_id = org.get('id')
            org_name = org.get('attributes', {}).get('name', 'Unknown')
            
            if not org_id:
                print(f"Skipping organization with missing ID: {org}")
                continue
            
            print(f"\nProcessing organization: {org_name} ({org_id})")
            
            # Get projects for this organization
            projects = self.get_projects_for_org(org_id)
            
            # Step 3: Process each project
            for project in projects:
                project_id = project.get('id')
                project_name = project.get('attributes', {}).get('name', 'Unknown')
                
                if not project_id:
                    print(f"Skipping project with missing ID: {project}")
                    continue
                
                print(f"    Processing project: {project_name} ({project_id})")
                
                # Get ignores for this project
                ignores_data = self.get_project_ignores(org_id, project_id)
                
                # Store the result
                result = {
                    'org_id': org_id,
                    'org_name': org_name,
                    'project_id': project_id,
                    'project_name': project_name,
                    'ignores': ignores_data
                }
                results.append(result)
                
                # Rate limiting delay
                time.sleep(delay)
        
        return results

    def test_specific_org(self, org_id: str) -> Dict[str, Any]:
        """
        Test if a specific organization ID is accessible via different methods.
        
        Args:
            org_id: The organization ID to test
            
        Returns:
            Dictionary with test results
        """
        results = {
            'org_id': org_id,
            'direct_access': False,
            'in_all_orgs': False,
            'projects_accessible': False,
            'ignores_accessible': False,
            'error_messages': []
        }
        
        # Test 1: Direct org access
        print(f"\nTesting direct access to org: {org_id}")
        url = f"{self.base_url}/rest/orgs/{org_id}"
        params = {"version": "2024-10-15"}
        
        try:
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                results['direct_access'] = True
                data = response.json()
                org_name = data.get('data', {}).get('attributes', {}).get('name', 'Unknown')
                print(f"✓ Direct access successful: {org_name}")
            else:
                results['error_messages'].append(f"Direct access failed: {response.status_code} - {response.text[:200]}")
                print(f"✗ Direct access failed: {response.status_code}")
        except Exception as e:
            results['error_messages'].append(f"Direct access error: {str(e)}")
            print(f"✗ Direct access error: {e}")
        
        # Test 2: Check if it appears in all orgs list
        print("Testing if org appears in all orgs list...")
        all_orgs = self.get_organizations()
        org_ids_found = [org.get('id') for org in all_orgs]
        
        if org_id in org_ids_found:
            results['in_all_orgs'] = True
            print("✓ Org found in all orgs list")
        else:
            print("✗ Org NOT found in all orgs list")
            print(f"Found {len(org_ids_found)} orgs total")
        
        # Test 3: Try to access projects directly
        print("Testing project access...")
        try:
            projects = self.get_projects_for_org(org_id)
            if projects:
                results['projects_accessible'] = True
                print(f"✓ Found {len(projects)} projects")
                
                # Test 4: Try ignores on first project
                if projects:
                    first_project_id = projects[0].get('id')
                    if first_project_id:
                        print("Testing ignores access...")
                        ignores = self.get_project_ignores(org_id, first_project_id)
                        if ignores or ignores == {}:  # Empty dict is still a successful response
                            results['ignores_accessible'] = True
                            print("✓ Ignores endpoint accessible")
                        else:
                            print("✗ Ignores endpoint failed")
            else:
                print("✗ No projects found or access denied")
        except Exception as e:
            results['error_messages'].append(f"Projects access error: {str(e)}")
            print(f"✗ Projects access error: {e}")
        
        return results

    def debug_org_discovery(self) -> Dict[str, Any]:
        """
        Debug function to understand org discovery issues.
        
        Returns:
            Dictionary with debugging information
        """
        debug_info = {
            'total_orgs_no_filter': 0,
            'total_groups': 0,
            'orgs_by_group': {},
            'all_org_ids': set()
        }
        
        print("=== DEBUGGING ORG DISCOVERY ===")
        
        # Get all orgs without group filter
        print("\n1. Getting all orgs (no group filter)...")
        all_orgs = self.get_organizations()
        debug_info['total_orgs_no_filter'] = len(all_orgs)
        
        for org in all_orgs:
            org_id = org.get('id')
            if org_id:
                debug_info['all_org_ids'].add(org_id)
        
        print(f"Found {len(debug_info['all_org_ids'])} unique org IDs without group filter")
        
        # Get all groups and try each one
        print("\n2. Getting all groups and checking orgs in each...")
        groups = self.get_groups()
        debug_info['total_groups'] = len(groups)
        
        for group in groups:
            group_id = group.get('id')
            group_name = group.get('attributes', {}).get('name', 'Unknown')
            
            if group_id:
                print(f"\nChecking group: {group_name} ({group_id})")
                group_orgs = self.get_organizations(group_id=group_id)
                debug_info['orgs_by_group'][group_id] = {
                    'name': group_name,
                    'org_count': len(group_orgs),
                    'org_ids': [org.get('id') for org in group_orgs if org.get('id')]
                }
                
                # Add these org IDs to our master set
                for org in group_orgs:
                    org_id = org.get('id')
                    if org_id:
                        debug_info['all_org_ids'].add(org_id)
        
        print(f"\n3. Total unique org IDs found across all methods: {len(debug_info['all_org_ids'])}")
        
        return debug_info


def flatten_ignores_data(ignores_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten the ignores data for CSV export.
    
    Args:
        ignores_data: The ignores response from the API
        
    Returns:
        Flattened dictionary with key ignore information
    """
    flattened = {}
    
    if not ignores_data:
        return {
            'total_ignores': 0,
            'ignore_details': 'No ignores data available'
        }
    
    # Count total ignores
    total_ignores = len(ignores_data) if isinstance(ignores_data, dict) else 0
    flattened['total_ignores'] = total_ignores
    
    # Extract key information from ignores
    ignore_summaries = []
    if isinstance(ignores_data, dict):
        for ignore_id, ignore_info in ignores_data.items():
            if isinstance(ignore_info, list) and ignore_info:
                # Handle cases where ignore_info is a list of dicts
                first_ignore = ignore_info[0]
                reason = first_ignore.get('reason', 'No reason provided')
                expires = first_ignore.get('expires', 'Never')
                created = first_ignore.get('created', 'Unknown')
                summary = f"ID: {ignore_id}, Reason: {reason}, Expires: {expires}, Created: {created}"
                ignore_summaries.append(summary)

    flattened['ignore_details'] = '; '.join(ignore_summaries) if ignore_summaries else 'No detailed ignore information'
    
    return flattened


def export_to_csv(results: List[Dict[str, Any]], filename: str) -> bool:
    """
    Export results to CSV format.
    
    Args:
        results: List of result dictionaries
        filename: Output filename
        
    Returns:
        True if successful, False otherwise
    """
    if not results:
        print("No results to export")
        return False
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Define CSV columns
            fieldnames = [
                'org_id',
                'org_name', 
                'project_id',
                'project_name',
                'total_ignores',
                'ignore_details'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write each result
            for result in results:
                # Flatten the ignores data
                flattened_ignores = flatten_ignores_data(result.get('ignores', {}))
                
                # Create CSV row
                csv_row = {
                    'org_id': result.get('org_id', ''),
                    'org_name': result.get('org_name', ''),
                    'project_id': result.get('project_id', ''),
                    'project_name': result.get('project_name', ''),
                    'total_ignores': flattened_ignores.get('total_ignores', 0),
                    'ignore_details': flattened_ignores.get('ignore_details', '')
                }
                
                writer.writerow(csv_row)
        
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
    
    # Debug option
    debug_mode = input("Do you want to run in debug mode to investigate missing orgs? (y/N): ").strip().lower()
    
    if debug_mode == 'y':
        # Debug missing org
        test_specific = input("Do you want to test access to a specific org ID? (y/N): ").strip().lower()
        if test_specific == 'y':
            org_id = input("Enter the org ID to test: ").strip()
            if org_id:
                client.test_specific_org(org_id)
        
        # Run comprehensive debugging
        run_full_debug = input("Run full org discovery debugging? This will check all groups (y/N): ").strip().lower()
        if run_full_debug == 'y':
            debug_info = client.debug_org_discovery()
            
            # Save debug info
            debug_filename = f"snyk_debug_info_{int(time.time())}.json"
            try:
                with open(debug_filename, 'w') as f:
                    # Convert set to list for JSON serialization
                    debug_info['all_org_ids'] = list(debug_info['all_org_ids'])
                    json.dump(debug_info, f, indent=2)
                print(f"\nDebug info saved to: {debug_filename}")
            except Exception as e:
                print(f"Error saving debug info: {e}")
        
        # Ask if user wants to continue with normal processing
        continue_normal = input("\nContinue with normal processing? (y/N): ").strip().lower()
        if continue_normal != 'y':
            return
    
    # Check if user wants to filter by group
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
    print("3. Fetch ignores for each project")
    print()
    
    # Process all projects
    results = client.process_all_projects(group_id=group_id, delay=0.1)
    
    # Summary
    print(f"\n{'='*50}")
    print("SUMMARY")
    print(f"{'='*50}")
    
    if not results:
        print("No projects were processed.")
        return

    print(f"Total projects processed: {len(results)}")
    
    # Count projects with ignores
    projects_with_ignores = sum(1 for r in results if r['ignores'] and any(r['ignores'].values()))
    print(f"Projects with ignores data: {projects_with_ignores}")
    
    # Ask about file exports
    print("\nExport options:")
    
    # JSON export option
    save_json = input("Save results to JSON file? (y/N): ").strip().lower()
    if save_json == 'y':
        json_filename = f"snyk_ignores_results_{int(time.time())}.json"
        try:
            with open(json_filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"JSON results saved to: {json_filename}")
        except Exception as e:
            print(f"Error saving JSON file: {e}")
    
    # CSV export option
    save_csv = input("Save results to CSV file? (y/N): ").strip().lower()
    if save_csv == 'y':
        csv_filename = f"snyk_ignores_results_{int(time.time())}.csv"
        if export_to_csv(results, csv_filename):
            print(f"CSV results saved to: {csv_filename}")
            print("CSV contains: org info, project info, ignore count, and ignore details")
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
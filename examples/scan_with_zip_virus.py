#!/usr/bin/env python3
"""
Example script demonstrating ZIP virus scanning via the API.

This script shows how to enable ZIP package virus scanning using VirusTotal.
"""

import asyncio
import httpx
import sys


async def scan_with_zip_virus(
    clawhub_url: str,
    api_base_url: str = "http://localhost:8000",
    vt_api_key: str | None = None,
):
    """
    Scan a skill from ClawHub URL with ZIP virus scanning enabled.
    
    Args:
        clawhub_url: ClawHub project URL
        api_base_url: Base URL of the Skill Scanner API
        vt_api_key: VirusTotal API key (optional, can use X-VirusTotal-Key header)
    
    Returns:
        Scan results as a dictionary
    """
    async with httpx.AsyncClient(timeout=300.0) as client:
        print(f"Scanning ClawHub skill with ZIP virus scanning: {clawhub_url}")
        print(f"API URL: {api_base_url}/scan-clawhub")
        print("-" * 60)
        
        headers = {}
        if vt_api_key:
            headers["X-VirusTotal-Key"] = vt_api_key
        
        try:
            response = await client.post(
                f"{api_base_url}/scan-clawhub",
                json={
                    "clawhub_url": clawhub_url,
                    "policy": "balanced",
                    "use_llm": False,
                    "use_virustotal": True,  # Scan individual binary files
                    "use_zip_virus": True,   # Scan the ZIP package itself
                    "vt_upload_files": False,  # Only check existing hashes
                },
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                print("\n✓ Scan completed successfully!")
                print(f"  Skill Name: {result['skill_name']}")
                print(f"  Scan ID: {result['scan_id']}")
                print(f"  Is Safe: {result['is_safe']}")
                print(f"  Max Severity: {result['max_severity']}")
                print(f"  Findings Count: {result['findings_count']}")
                print(f"  Scan Duration: {result['scan_duration_seconds']:.2f}s")
                
                if result['findings_count'] > 0:
                    print("\n  Findings:")
                    for i, finding in enumerate(result['findings'], 1):
                        print(f"    {i}. [{finding['severity']}] {finding['title']}")
                        print(f"       Analyzer: {finding['analyzer']}")
                        if finding.get('file_path'):
                            print(f"       File: {finding['file_path']}")
                        if finding.get('metadata', {}).get('file_hash'):
                            print(f"       Hash: {finding['metadata']['file_hash']}")
                
                return result
            else:
                print(f"\n✗ Scan failed with status code: {response.status_code}")
                try:
                    error_detail = response.json().get('detail', 'Unknown error')
                    print(f"  Error: {error_detail}")
                except:
                    print(f"  Response text: {response.text}")
                return None
                
        except httpx.HTTPError as e:
            print(f"\n✗ HTTP error occurred: {e}")
            import traceback
            traceback.print_exc()
            return None
        except Exception as e:
            print(f"\n✗ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return None


async def main():
    """Main function to demonstrate ZIP virus scanning."""
    import os
    
    # Check for VirusTotal API key
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        print("Warning: VIRUSTOTAL_API_KEY environment variable not set.")
        print("ZIP virus scanning requires a VirusTotal API key.")
        print("Set it with: export VIRUSTOTAL_API_KEY=your_key")
        print()
    
    # Example ClawHub URLs
    examples = [
        "https://clawhub.ai/Asleep123/caldav-calendar",
        "https://clawhub.ai/steipete/nano-pdf",
    ]
    
    # Check if a custom URL was provided
    if len(sys.argv) > 1:
        clawhub_url = sys.argv[1]
    else:
        print("Available example URLs:")
        for i, url in enumerate(examples, 1):
            print(f"  {i}. {url}")
        
        choice = input("\nSelect an example (1-2) or enter a custom URL: ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(examples):
            clawhub_url = examples[int(choice) - 1]
        elif choice.startswith("https://clawhub.ai/"):
            clawhub_url = choice
        else:
            print("Invalid choice. Using first example.")
            clawhub_url = examples[0]
    
    # Scan the skill with ZIP virus scanning enabled
    result = await scan_with_zip_virus(
        clawhub_url=clawhub_url,
        vt_api_key=vt_api_key,
    )
    
    if result:
        print("\n" + "=" * 60)
        print("Scan completed. ZIP virus scanning was enabled.")
        print("=" * 60)
    else:
        print("\nScan failed. Please check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

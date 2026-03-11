#!/usr/bin/env python3
"""
Example script demonstrating ClawHub URL scanning via the API.

This script shows how to scan a skill package directly from ClawHub
without manually downloading and uploading the file.
"""

import asyncio
import httpx
import sys


async def scan_clawhub_skill(
    clawhub_url: str,
    api_base_url: str = "http://localhost:8000",
    policy: str = "balanced",
    use_llm: bool = False,
):
    """
    Scan a skill from ClawHub URL.
    
    Args:
        clawhub_url: ClawHub project URL (e.g., https://clawhub.ai/username/project)
        api_base_url: Base URL of the Skill Scanner API
        policy: Scan policy (strict, balanced, or permissive)
        use_llm: Whether to enable LLM analysis
    
    Returns:
        Scan results as a dictionary
    """
    async with httpx.AsyncClient(timeout=300.0) as client:
        print(f"Scanning ClawHub skill: {clawhub_url}")
        print(f"API URL: {api_base_url}/scan-clawhub")
        print(f"Policy: {policy}")
        print(f"LLM Analysis: {'Enabled' if use_llm else 'Disabled'}")
        print("-" * 60)
        
        try:
            response = await client.post(
                f"{api_base_url}/scan-clawhub",
                json={
                    "clawhub_url": clawhub_url,
                    "policy": policy,
                    "use_llm": use_llm,
                    "llm_provider": "anthropic",
                    "use_behavioral": False,
                    "use_virustotal": False,
                    "use_aidefense": False,
                    "use_trigger": False,
                    "enable_meta": False,
                }
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
                    for i, finding in enumerate(result['findings'][:5], 1):
                        print(f"    {i}. [{finding['severity']}] {finding['title']}")
                        if finding.get('file_path'):
                            print(f"       File: {finding['file_path']}")
                    
                    if result['findings_count'] > 5:
                        print(f"    ... and {result['findings_count'] - 5} more findings")
                
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
    """Main function to demonstrate ClawHub scanning."""
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
    
    # Scan the skill
    result = await scan_clawhub_skill(
        clawhub_url=clawhub_url,
        policy="balanced",
        use_llm=False,  # Set to True if you have LLM API keys configured
    )
    
    if result:
        print("\n" + "=" * 60)
        print("Scan completed. Full results available in the response.")
        print("=" * 60)
    else:
        print("\nScan failed. Please check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

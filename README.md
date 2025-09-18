
## Snyk API Chain - Ignores

This tool allows you to pull all of the Ignores from the Snyk API. It iterates through the Group to find the Organizations, then iterates through each Organization to find Projects, then for each of those pulls the ignores. Output options are json or csv.

    SETUP INSTRUCTIONS:
    
    
    1. INSTALL REQUIRED PACKAGES:
       - Create a virtual environment, 'python3 -m venv snyk-api-chain-ignores-env'
       - Activate it, 'source snyk-api-chain-ignores-env/bin/activate'
       - Install requirements ' pip install requests'

    2. SETUP THE ENVIRONMENT:
       - Make sure you have an environment variable set for SNYK_TOKEN, or export SNYK_TOKEN=<your_token>. The token permissions will dictate which Organizations data can be pulled from so if you're missing information it's likely due to permissions.
       - Currently the script points to https://api.snyk.io. If you're using another region or private cloud update the line self.base_url = "https://api.snyk.io" with your host.

    2. RUN THE SCRIPT:
       - Run the script with 'python ./ignores.py' from the project folder.
       - Follow the prompts.



## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

**You are free to:**
- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material

**Under the following terms:**
- Attribution — You must give appropriate credit
- NonCommercial — You may not use the material for commercial purposes
- ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license

See the [LICENSE](LICENSE) file for details.
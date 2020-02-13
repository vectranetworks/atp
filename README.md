# Microsoft ATP Integration

atp.py is a python script that provides an API level integration between Microsoft ATP and Cognito Detect.
Contextual information is obtained from ATP and applied to a host in the form of tags.  This is triggered manually
by adding a specified tag to a host, or automatically based on the host's Threat and Certainty scoring.
Host enforcement (blocking/unblocking) can be triggered by manually adding a specified tag to a host.

## Prerequisites

Python3, requests, validators, python-jose, and Vectra API Tools (vat) modules.
Required modules are installed automatically when following the procedures outlined.  

A Cognito Detect API key is required and can be generated by going to **My Profile** and Generating an API token. 

An ATP Tenant ID, App ID, and App Secret are required.

## Setup
Manually clone or download using git, run setup or install with pip3:
```
git clone https://github.com/vectranetworks/atp.git
python3 setup.py install
```
or
```
git clone https://github.com/vectranetworks/atp.git
pip3 install -e .
```

Or Install directly from github utilizing pip3:
```
pip3 install git+https://github.com/vectranetworks/atp.git
```

## Configuration
Edit the config.py file and adjust the required variables according to your environment.  A local install will typically
 install in the following path ***~/.local/lib/\<python\>/site-packages/atp***.  Running the script without a 
 valid config in config.py will throw an exception which indicates the full path to the script and config.py file.


## Running

When ran, the script needs to be supplied one or more parameters.  Examples:


```
atp --tag host_context
atp --tag host_context --tc 75 75
```

The --tag flag will query Detect for active hosts that have the specified tag (host_context in this example), 
obtain contextual information from ATP, and apply the contextual information as Host Tags back to the host. 

The --tc flag allows a Host's Threat and Certainty scoring thresholds to be supplied for contextual tagging.  Flags can
be combined.

### Typical Usage
```
atp --tag host_context --tc 75 75 --blocktag block --unblocktag unblock
```
Specifying multiple flags allows the integration to cover multiple use cases. 

### Recommendations
To test the desired use cases, run the atp script from the CLI for testing.  To run in production, the script 
is designed to be called via a cron job.
 
 
## Help Output

usage: atp.py [-h] [--tc TC TC] [--tag TAG] [--blocktag BLOCKTAG] [--unblocktag UNBLOCKTAG] [--verbose]

Poll Cognito for tagged hosts, extracts ATP contextual information.  Block or unblock hosts per tags.

optional arguments:  
  -h, --help            show this help message and exit  
  --tc TC TC            Poll for hosts with threat and certainty scores >=, eg --tc 50 50  
  --tag TAG             Enrichment host tag to search for  
  --blocktag BLOCKTAG   Block hosts with this tag  
  --unblocktag UNBLOCKTAG Unblock hosts with this tag
  --verbose             Verbose logging  


## Authors

* **Matt Pieklik** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
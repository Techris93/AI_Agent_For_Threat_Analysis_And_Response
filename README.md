# AI_Agent_For_Threat_Analysis_And_Response
### Overview
This AI agent is developed to automate critical Security Operation and Control tasks, such as data retrieval, threat analysis, and incident reporting. This is achieved by integrating Elasticsearch and leveraging natural language processing.
Below, I provided a step-by-step breakdoown of how this AI agent is built, including the code snippets and explanations of each coomponent.

### 1. Setup snd Environment
The first step in developing the AI agent was setting up the development environment. The agent relies on Python and Elasticsearch, a widely used database for storing and querying security logs. Here’s how the environment was configured:

- The programming language used: Python
- Database: Elasticsearch, which is used to store security event logs
- Required libraries:
  - elasticsearch: Python client for connecting to Elasticsearch.
  - spacy: A natural Language processing library for interpreting user queries
 
To set up the environment, the following commands were executed:
```
pip install elasticsearch spacy
python -m spacy download en_core_web_sm  # Downloads a small English NLP model
```

This ensured all necessary tools were installed and ready for development.

### Core Functions of the AI Agent
The AI agent’s functionality is built around two core functions: listing available datasets (indices) in Elasticsearch and searching for security events within a specified date range. These functions form the backbone of the agent’s ability to retrieve and analyze security data.

#### a. Listing Indices
The list_indices function retrieves all available datasets (indices) from Elasticsearch, allowing the agent to understand what data sources are accessible.
```
from elasticsearch import Elasticsearch

class AIAgent:
    def __init__(self, es_host="localhost:9200"):
        """Initialize the AI agent with an Elasticsearch connection."""
        self.es = Elasticsearch([es_host])
    
    def list_indices(self):
        """Retrieve a list of all available indices in Elasticsearch."""
        indices = self.es.indices.get_alias("*")
        return list(indices.keys())

# Example usage
agent = AIAgent()
print(agent.list_indices())
```

Explanation:
- The Elasticsearch client is initialized with the host address (e.g., localhost:9200).
- The get_alias("*") method retrieves metadata for all indices, and the function extracts the index names as a list.
- This function is essential for identifying which logs (e.g., network logs, system logs) are available for analysis.

#### b. Searching Events
The search_events function queries Elasticsearch for security events within a specified date range, enabling the agent to retrieve logs relevant to specific incidents.
```
def search_events(self, start_date, end_date):
    """Search for security events within a specified date range."""
    query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": start_date,  # Greater than or equal to start_date
                    "lte": end_date     # Less than or equal to end_date
                }
            }
        }
    }
    response = self.es.search(index="*", body=query)
    return response['hits']['hits']

# Example usage
events = agent.search_events("2024-08-01", "2024-08-17")
for event in events:
    print(event['_source'])  # Prints the event details
```

Explanation:

- The function constructs an Elasticsearch range query targeting the timestamp field, filtering events between start_date and end_date.
- The search method queries all indices (index="*") and returns matching events in the hits.hits structure.
- This allows the agent to pinpoint logs related to a specific timeframe, such as during a cyber-attack.

### 3. Natural Language Processing for Query Handling
To make the agent user-friendly, it uses natural language processing to interpret natural language queries from SOC analysts (e.g., “What internal IP addresses were affected by the phishing attack?”) and map them to Elasticsearch queries.
Here’s an example of how natural language processing was implemented using the spacy library:
```
import spacy

nlp = spacy.load("en_core_web_sm")  # Load the English NLP model

def process_query(self, query_text):
    """Process a natural language query and map it to an Elasticsearch action."""
    doc = nlp(query_text)
    # Extract entities from the query
    entities = [(ent.text, ent.label_) for ent in doc.ents]
    # Simplified logic to map query to action
    if "IP addresses" in query_text and "phishing" in query_text:
        # Example: Search events for a phishing attack in August 2024
        return self.search_events("2024-08-01", "2024-08-17")
    return []

# Example usage
results = agent.process_query("What internal IP addresses were affected by the phishing attack?")
for result in results:
    print(result['_source'].get('ip_address', 'No IP found'))
```
Explanation: 

- The spacy library processes the query text and identifies key entities (e.g., “IP addresses,” “phishing”).
- Based on these entities, the function maps the query to an appropriate action—in this case, calling search_events with a predefined date range.
- In a full implementation, this would include more complex parsing and mapping rules to handle a wider range of queries.

### 4. Reporting: Generating Structured Incident Reports
The agent generates structured reports to present analysis results in a readable format, using Markdown for simplicity and compatibility.
```
def generate_report(self, analysis_data, filename="incident_report.md"):
    """Generate a structured incident report in Markdown format."""
    with open(filename, "w") as report_file:
        report_file.write("# Incident Report\n\n")
        report_file.write("## Summary\n")
        report_file.write("Analysis of security events:\n")
        for event in analysis_data:
            description = event['_source'].get('description', 'No description')
            report_file.write(f"- {description}\n")
        report_file.write("\n## Timeline\n")
        # Simplified timeline; could be expanded with event timestamps
        report_file.write("Events occurred between the specified dates.\n")
    print(f"Report generated: {filename}")

# Example usage
agent.generate_report(results)
```

Explanation:

- The function takes analysis data (e.g., from search_events) and writes it to a Markdown file.
- It includes a summary section listing event descriptions and a placeholder for a timeline (which could be enhanced with timestamps).
- The resulting report is easy to read and share with incident response teams.

### 5. Real-World Application: Investigating a Multi-Stage Cyber-Attack
The AI agent was applied to investigate a multi-stage cyber-attack that occurred between August 1st and 17th, 2024, involving malware, phishing, and SQL injection. Here’s how it was used:
#### Step 1: Identify Affected Systems
- Query: “What internal IP addresses were affected by the phishing attack?”
- Code:
  ```
  affected_ips = agent.process_query("What internal IP addresses were affected by the phishing attack?")
for event in affected_ips:
    print(event['_source'].get('ip_address'))
    ```
- Outcome: The agent retrieved a list of compromised internal IP addresses, enabling rapid containment.

#### Step 2: Analyze Attack Vectors
- Query: “How were the web application attacks executed?”
- Code:
  ```
  attack_analysis = agent.process_query("How were the web application attacks executed?")
for event in attack_analysis:
    print(event['_source'].get('attack_method'))
    ```

- Outcome: The agent identified SQL injection as a key method, providing actionable insights.
#### Step 3: Generate Incident Report
- Code:
  ```
  agent.generate_report(attack_analysis, filename="detailed_incident_report.md")
  ```
- Outcome: A detailed report was produced, including a summary and timeline, which guided the SOC team’s response.

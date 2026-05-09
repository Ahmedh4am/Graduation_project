#!/usr/bin/env python3

import requests
import json
import urllib.parse
from urllib.parse import urlparse, urljoin

DEFAULT_TIMEOUT = 10

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/api/graph",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/api/v1/graph",
    "/api/v2/graph",
    "/query",
    "/api/query"
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

FIELD_SUGGESTION_QUERY = """
query {
  __typename
  invalidFieldThatDoesNotExist
}
"""

BATCH_QUERY = """
[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]
"""

ALIAS_OVERLOAD_QUERY = """
query {
  alias1: __typename
  alias2: __typename
  alias3: __typename
  alias4: __typename
  alias5: __typename
  alias6: __typename
  alias7: __typename
  alias8: __typename
  alias9: __typename
  alias10: __typename
}
"""


def detect_graphql_endpoints(base_url, timeout=DEFAULT_TIMEOUT, verify=True):
    """Detect potential GraphQL endpoints"""
    endpoints = []
    session = requests.Session()

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for endpoint in GRAPHQL_ENDPOINTS:
        url = urljoin(base, endpoint)
        try:
            # Try GET request first
            r = session.get(url, timeout=timeout, verify=verify)
            if r.status_code == 200:
                content = r.text.lower()
                if any(keyword in content for keyword in ['graphql', 'graphiql', 'query', '__schema']):
                    endpoints.append(url)
                    continue

            # Try POST with introspection query
            headers = {'Content-Type': 'application/json'}
            data = {'query': '{ __typename }'}
            r = session.post(url, json=data, headers=headers, timeout=timeout, verify=verify)
            if r.status_code == 200:
                try:
                    response_json = r.json()
                    if 'data' in response_json and '__typename' in response_json['data']:
                        endpoints.append(url)
                except:
                    pass

        except Exception:
            continue

    return endpoints


def test_introspection(endpoint, timeout=DEFAULT_TIMEOUT, verify=True):
    """Test if GraphQL introspection is enabled"""
    findings = []
    session = requests.Session()

    try:
        headers = {'Content-Type': 'application/json'}
        data = {'query': INTROSPECTION_QUERY}

        r = session.post(endpoint, json=data, headers=headers, timeout=timeout, verify=verify)

        if r.status_code == 200:
            try:
                response_json = r.json()
                if 'data' in response_json and '__schema' in response_json['data']:
                    findings.append({
                        "type": "Introspection Enabled",
                        "severity": "Medium",
                        "details": "GraphQL introspection is enabled, which may leak schema information"
                    })
                elif 'errors' in response_json:
                    # Introspection might be disabled
                    pass
            except:
                pass

    except Exception:
        pass

    return findings


def test_field_suggestions(endpoint, timeout=DEFAULT_TIMEOUT, verify=True):
    """Test for field suggestions (did you mean?)"""
    findings = []
    session = requests.Session()

    try:
        headers = {'Content-Type': 'application/json'}
        data = {'query': FIELD_SUGGESTION_QUERY}

        r = session.post(endpoint, json=data, headers=headers, timeout=timeout, verify=verify)

        if r.status_code == 200:
            try:
                response_json = r.json()
                if 'errors' in response_json:
                    for error in response_json['errors']:
                        if 'did you mean' in str(error).lower() or 'suggestions' in str(error).lower():
                            findings.append({
                                "type": "Field Suggestions Enabled",
                                "severity": "Low",
                                "details": "GraphQL provides field suggestions which may aid attackers"
                            })
                            break
            except:
                pass

    except Exception:
        pass

    return findings


def test_batch_queries(endpoint, timeout=DEFAULT_TIMEOUT, verify=True):
    """Test for batch query support"""
    findings = []
    session = requests.Session()

    try:
        headers = {'Content-Type': 'application/json'}
        data = json.loads(BATCH_QUERY.strip())

        r = session.post(endpoint, json=data, headers=headers, timeout=timeout, verify=verify)

        if r.status_code == 200:
            try:
                response_json = r.json()
                if isinstance(response_json, list) and len(response_json) > 1:
                    findings.append({
                        "type": "Batch Queries Supported",
                        "severity": "Low",
                        "details": "GraphQL supports batch queries which may be abused for DoS"
                    })
            except:
                pass

    except Exception:
        pass

    return findings


def test_alias_overload(endpoint, timeout=DEFAULT_TIMEOUT, verify=True):
    """Test for alias overload protection"""
    findings = []
    session = requests.Session()

    try:
        headers = {'Content-Type': 'application/json'}
        data = {'query': ALIAS_OVERLOAD_QUERY}

        r = session.post(endpoint, json=data, headers=headers, timeout=timeout, verify=verify)

        if r.status_code == 200:
            try:
                response_json = r.json()
                if 'data' in response_json and len(response_json['data']) > 5:
                    findings.append({
                        "type": "Alias Overload Possible",
                        "severity": "Low",
                        "details": "Large number of aliases allowed, potential for DoS"
                    })
            except:
                pass

    except Exception:
        pass

    return findings


def scan_graphql_single(url, timeout=DEFAULT_TIMEOUT, verify=True):
    """Scan a single URL for GraphQL vulnerabilities"""
    findings = []

    # Detect GraphQL endpoints
    endpoints = detect_graphql_endpoints(url, timeout, verify)

    if not endpoints:
        return findings

    for endpoint in endpoints:
        findings.append({
            "type": "GraphQL Endpoint Found",
            "severity": "Info",
            "details": f"Potential GraphQL endpoint: {endpoint}"
        })

        # Test various vulnerabilities
        findings.extend(test_introspection(endpoint, timeout, verify))
        findings.extend(test_field_suggestions(endpoint, timeout, verify))
        findings.extend(test_batch_queries(endpoint, timeout, verify))
        findings.extend(test_alias_overload(endpoint, timeout, verify))

    return findings


def run_graphql_scan_file(input_file, timeout=DEFAULT_TIMEOUT, verify=True):
    """Scan multiple URLs from a file"""
    try:
        with open(input_file, "r") as f:
            urls = [u.strip() for u in f if u.strip()]

        for url in urls:
            print(f"\n[*] Testing: {url}")

            results = scan_graphql_single(url, timeout, verify)

            if results:
                for r in results:
                    print(f"  [!] {r['severity']} | {r['type']}")
                    print(f"      {r['details']}")
            else:
                print("  [-] No GraphQL endpoints or issues found")

    except Exception as e:
        print(f"[!] Error: {e}")
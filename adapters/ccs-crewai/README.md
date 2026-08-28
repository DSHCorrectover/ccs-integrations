# ccs-crewai

CCS (Correctover Conformance Shape) runtime receipts for CrewAI agents.

## Install

```bash
pip install ccs-crewai
```

## Quick start

```python
from ccs_crewai import CCSConfig, CCSGuardrailProvider, PolicyDecision

def my_policy(tool_name, tool_args, runtime_context=None):
    if tool_name == "dangerous_tool":
        return PolicyDecision(allowed=False, reason="blocked by policy")
    return PolicyDecision.ALLOW

config = CCSConfig(
    seed=b"my-app-seed",
    issuer="my-agent",
    audience="audit-log",
    policy=my_policy,
)

provider = CCSGuardrailProvider(config)
result = provider.intercept_tool_call(
    tool_name="search",
    tool_args={"q": "hello"},
    runner=lambda: search_tool(q="hello"),
)
```

## CLI verification

```bash
ccs-crewai-verify receipt.json
ccs-crewai-verify --chain receipt.json
```

## License

MIT

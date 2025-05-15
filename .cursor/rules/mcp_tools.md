# Cursor Rules for MCP Tool Generation

## Tool Definition Guidelines

1. **Use the @mcp.tool() decorator**
   - All tools must be defined using the `@mcp.tool()` decorator
   - This properly registers the function as an MCP tool
   - Include proper type hints for parameters and return values

2. **Methods must be async**
   - All tool methods should be defined as async functions
   - Use `async def` for all tool definitions
   - Use appropriate async libraries and patterns (e.g., httpx.AsyncClient instead of requests)

3. **Include descriptive docstrings**
   - Each tool must have a clear, descriptive docstring
   - Docstrings should explain what the tool does and describe parameters

## Examples of correct tool implementations:

```python
@mcp.tool()
async def calculate_bmi(weight_kg: float, height_m: float) -> float:
    """Calculate BMI given weight in kg and height in meters"""
    return weight_kg / (height_m**2)


@mcp.tool()
async def fetch_weather(city: str) -> str:
    """Fetch current weather for a city"""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://api.weather.com/{city}")
        return response.text
```

## Common Mistakes to Avoid

1. **Don't use synchronous functions**
   - Incorrect: `def my_tool():`
   - Correct: `async def my_tool():`

2. **Don't forget the decorator**
   - Incorrect: `async def my_tool():`
   - Correct: `@mcp.tool()\nasync def my_tool():`

3. **Don't use blocking HTTP libraries**
   - Incorrect: `requests.get(...)`
   - Correct: `async with httpx.AsyncClient() as client: await client.get(...)`

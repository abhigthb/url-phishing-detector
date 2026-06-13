# PhishGuard Architecture (V1)

## Heuristic Registry Pattern
To ensure the engine remains extensible, all heuristics inherit from `BaseHeuristic`. 
The application discovers logic automatically at runtime via the `@register` decorator.

### Adding a New Heuristic
1. Create a class inheriting from `BaseHeuristic`.
2. Implement the `check(self, url)` method.
3. Return a `HeuristicResult(triggered: bool, score_contribution: int, evidence: str)`.
4. Decorate the class with `@register`.

Zero engine modifications are required to deploy new rules.
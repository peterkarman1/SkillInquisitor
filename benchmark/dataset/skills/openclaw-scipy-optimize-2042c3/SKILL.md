---
name: scipy-optimize
description: Use scipy.optimize for minimization, least-squares fitting, root finding, linear programming, and global optimization with correct method selection, constraints, and bounds.
---

# scipy.optimize -- Method Selection, Constraints, and Common Pitfalls

## Method Selection for minimize()

Choosing the wrong method is the most common mistake. The method determines what kinds of problems can be solved.

### Decision Guide

| Problem Type | Recommended Method | Notes |
|---|---|---|
| Unconstrained, smooth, gradient available | `BFGS` | Default for unconstrained. Fast convergence. |
| Unconstrained, no gradient | `Nelder-Mead` | Derivative-free. Slow but robust. |
| Unconstrained, Hessian available | `Newton-CG`, `trust-exact` | Fastest convergence near solution. |
| Bounds only (box constraints) | `L-BFGS-B` | Handles large problems well. |
| Bounds + general constraints | `SLSQP` or `trust-constr` | `SLSQP` is faster for small problems; `trust-constr` for large or when you have Hessian. |
| Inequality constraints only, no gradient | `COBYLA` | Derivative-free constrained optimization. |
| Large-scale with sparse Hessian | `trust-constr` | Supports sparse matrices. |

### Critical: Bounds Silently Change the Method

If you pass `bounds` without specifying `method`, scipy silently switches from `BFGS` to `L-BFGS-B`. This is usually fine, but can produce different convergence behavior:

```python
from scipy.optimize import minimize
import numpy as np

def objective(x):
    return (x[0] - 1)**2 + (x[1] - 2.5)**2

# No bounds: uses BFGS by default
res1 = minimize(objective, [0, 0])

# With bounds: silently switches to L-BFGS-B
res2 = minimize(objective, [0, 0], bounds=[(0, None), (0, None)])

# Explicit is better -- avoids surprises
res3 = minimize(objective, [0, 0], method='L-BFGS-B',
                bounds=[(0, None), (0, None)])
```

## Specifying Bounds

Two formats exist. The modern `Bounds` class is cleaner for complex problems:

```python
from scipy.optimize import minimize, Bounds

# Old style: list of (min, max) tuples. Use None for unbounded.
bounds_old = [(0, 10), (None, 5), (0, None)]

# New style: Bounds object. Use -np.inf/np.inf for unbounded.
bounds_new = Bounds(lb=[0, -np.inf, 0], ub=[10, 5, np.inf])

# Both work with minimize:
res = minimize(objective, x0, bounds=bounds_old)
res = minimize(objective, x0, bounds=bounds_new)
```

The number of bounds must match `len(x0)` -- a mismatch raises `ValueError`.

## Specifying Constraints

### Dictionary Format (works with SLSQP and COBYLA)

```python
# Equality constraint: x[0] + x[1] = 1
eq_constraint = {'type': 'eq', 'fun': lambda x: x[0] + x[1] - 1}

# Inequality constraint: x[0] - x[1] >= 0  (convention: fun(x) >= 0)
ineq_constraint = {'type': 'ineq', 'fun': lambda x: x[0] - x[1]}

res = minimize(objective, x0, method='SLSQP',
               constraints=[eq_constraint, ineq_constraint])
```

The inequality convention is `fun(x) >= 0` (not `<= 0`). Getting this backwards silently gives wrong results.

### LinearConstraint and NonlinearConstraint (works with trust-constr)

```python
from scipy.optimize import LinearConstraint, NonlinearConstraint

# Linear constraint: 1 <= x[0] + 2*x[1] <= 10
linear = LinearConstraint([[1, 2]], lb=1, ub=10)

# Nonlinear constraint: 0 <= x[0]**2 + x[1] <= 5
nonlinear = NonlinearConstraint(lambda x: x[0]**2 + x[1], lb=0, ub=5)

res = minimize(objective, x0, method='trust-constr',
               constraints=[linear, nonlinear])
```

Mistake -- using `LinearConstraint` with `SLSQP`:

```python
# WRONG: SLSQP does not accept LinearConstraint objects
minimize(objective, x0, method='SLSQP',
         constraints=LinearConstraint([[1, 2]], 1, 10))  # TypeError

# RIGHT: use dict format with SLSQP
minimize(objective, x0, method='SLSQP',
         constraints={'type': 'ineq', 'fun': lambda x: x[0] + 2*x[1] - 1})
```

## Jacobian and Hessian Specification

### Jacobian

The Jacobian (gradient) of the objective must be shape `(n,)` -- the same shape as `x`:

```python
def objective(x):
    return x[0]**2 + x[1]**2

def jacobian(x):
    return np.array([2*x[0], 2*x[1]])  # shape (n,), NOT (1, n)

res = minimize(objective, [1, 1], method='BFGS', jac=jacobian)
```

You can also use finite difference approximation:

```python
# '2-point' (default), '3-point' (more accurate), or 'cs' (complex step)
res = minimize(objective, [1, 1], method='BFGS', jac='3-point')
```

### Combined Objective and Gradient

When objective and gradient share computation, return both to avoid redundant work:

```python
def objective_and_grad(x):
    shared = np.exp(x)  # expensive computation used by both
    f = np.sum(shared)
    g = shared  # gradient reuses the same exp(x)
    return f, g

res = minimize(objective_and_grad, x0, method='BFGS', jac=True)
```

Setting `jac=True` tells minimize that `fun` returns `(f, grad)`.

### Hessian

The Hessian must be shape `(n, n)`:

```python
def hessian(x):
    return np.array([[2.0, 0.0],
                     [0.0, 2.0]])  # shape (n, n)

res = minimize(objective, [1, 1], method='Newton-CG',
               jac=jacobian, hess=hessian)
```

## Variable Scaling

Variables on very different scales cause poor convergence. A parameter in the range [1e-6, 1e-5] and another in [1e3, 1e4] will make the optimizer struggle:

```python
# BAD: x[0] ~ 1e-6, x[1] ~ 1e3
res = minimize(objective, [1e-6, 1e3])

# BETTER: rescale so all variables are O(1)
def scaled_objective(x_scaled):
    x_real = x_scaled * np.array([1e-6, 1e3])  # unscale
    return original_objective(x_real)

res = minimize(scaled_objective, [1.0, 1.0])
x_solution = res.x * np.array([1e-6, 1e3])
```

## least_squares: Nonlinear Least-Squares with Bounds

### Method Selection

| Method | Bounds | Sparse Jacobian | Best For |
|---|---|---|---|
| `'lm'` | No | No | Small unconstrained problems. Fastest. |
| `'trf'` | Yes | Yes | General purpose. Default. |
| `'dogbox'` | Yes | Yes | Small bounded problems. |

### Basic Usage

```python
from scipy.optimize import least_squares

# fun must return residual VECTOR, not scalar cost
def residuals(x, t, y):
    return x[0] * np.exp(-x[1] * t) - y

res = least_squares(residuals, x0=[1, 0.1], args=(t_data, y_data),
                    bounds=([0, 0], [np.inf, np.inf]))
```

### Robust Fitting with Loss Functions

Use non-linear loss functions to reduce outlier influence:

```python
# 'soft_l1' is a good default for robust fitting
res = least_squares(residuals, x0, args=(t, y),
                    loss='soft_l1', f_scale=0.1)
# f_scale sets the transition between inlier/outlier residuals
```

Available losses: `'linear'` (default), `'soft_l1'`, `'huber'`, `'cauchy'`, `'arctan'`.
Only `'linear'` works with method `'lm'`.

### Jacobian Shape

The Jacobian for `least_squares` is `(m, n)` -- m residuals by n parameters. This is different from `minimize` where the Jacobian is `(n,)`:

```python
def jac(x, t, y):
    # m residuals, 2 parameters -> shape (m, 2)
    J = np.empty((len(t), 2))
    J[:, 0] = np.exp(-x[1] * t)
    J[:, 1] = -x[0] * t * np.exp(-x[1] * t)
    return J

res = least_squares(residuals, x0, jac=jac, args=(t_data, y_data))
```

## curve_fit: Convenience Wrapper for least_squares

```python
from scipy.optimize import curve_fit

def model(x, a, b):
    return a * np.exp(-b * x)

# Returns optimal parameters and covariance matrix
popt, pcov = curve_fit(model, x_data, y_data, p0=[1, 0.1])

# Parameter uncertainties (1-sigma)
perr = np.sqrt(np.diag(pcov))
```

### Weighted Fitting with sigma

```python
# sigma = measurement uncertainties (standard deviations)
popt, pcov = curve_fit(model, x_data, y_data,
                       sigma=uncertainties,
                       absolute_sigma=True)
```

`absolute_sigma=True` means `sigma` values are actual measurement uncertainties.
`absolute_sigma=False` (default) means `sigma` values are relative weights -- pcov is scaled so reduced chi-squared = 1. This default is almost always wrong for physical measurements.

## Global Optimization

Local methods find the nearest minimum. For multimodal functions, use global optimizers:

```python
from scipy.optimize import differential_evolution, dual_annealing

# differential_evolution: requires bounds, no gradient needed
# Good default for most global optimization problems
result = differential_evolution(objective, bounds=[(0, 10), (0, 10)])

# dual_annealing: can be faster for smooth functions
result = dual_annealing(objective, bounds=[(0, 10), (0, 10)])

# basinhopping: good when you have a good local minimizer
from scipy.optimize import basinhopping
result = basinhopping(objective, x0=[5, 5], minimizer_kwargs={'method': 'L-BFGS-B'})
```

`differential_evolution` applies `minimize` polishing by default (`polish=True`). This refines the best result with L-BFGS-B. Disable it for speed if you do not need high precision.

## Root Finding

```python
from scipy.optimize import root

def equations(x):
    return [x[0] + 0.5 * (x[0] - x[1])**3 - 1.0,
            0.5 * (x[1] - x[0])**3 + x[1]]

sol = root(equations, [0, 0], method='hybr')  # default: Powell hybrid
```

Methods: `'hybr'` (default), `'lm'` (overdetermined systems), `'krylov'` (large systems).

## Linear Programming

```python
from scipy.optimize import linprog

# linprog MINIMIZES. To maximize, negate c and negate res.fun.
c = [-1, -2]  # maximize x + 2y
A_ub = [[1, 1], [-1, 0], [0, -1]]
b_ub = [6, 0, 0]
res = linprog(c, A_ub=A_ub, b_ub=b_ub, method='highs')
```

Default method is `'highs'`. The old `'simplex'` and `'revised simplex'` are deprecated.

## Common Mistakes Summary

1. **Constraint sign convention**: `{'type': 'ineq'}` means `fun(x) >= 0`, not `<= 0`.
2. **Jacobian shape**: `minimize` wants `(n,)`, `least_squares` wants `(m, n)`.
3. **least_squares returns residuals**: The function must return a vector of residuals, not a scalar cost.
4. **absolute_sigma default is False**: `curve_fit` scales covariance by default. Set `absolute_sigma=True` for real uncertainties.
5. **Bounds trigger method switch**: Passing `bounds` without `method` silently changes from `BFGS` to `L-BFGS-B`.
6. **Not scaling variables**: Parameters on different scales cause poor convergence. Rescale to O(1).
7. **linprog only minimizes**: To maximize, negate the objective vector and negate the result.
8. **Method-constraint mismatch**: `SLSQP` uses dict constraints; `trust-constr` uses `LinearConstraint`/`NonlinearConstraint`. Mixing them raises errors.
9. **Forgetting to check res.success**: Always check `res.success` and `res.message`. A returned result does not mean convergence.
10. **Using deprecated methods**: `linprog` methods `'simplex'` and `'revised simplex'` are deprecated. Use `'highs'`.

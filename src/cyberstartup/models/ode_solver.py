import torch

alpha = [0.0, 1.0/5.0, 3.0/10.0, 4.0/5.0, 8.0/9.0, 1.0, 1.0]

beta = [
    [],
    [1.0/5.0],
    [3.0/40.0, 9.0/40.0],
    [44.0/45.0, -56.0/15.0, 32.0/9.0],
    [19372.0/6561.0, -25360.0/2187.0, 64448.0/6561.0, -212.0/729.0],
    [9017.0/3168.0, -355.0/33.0, 46732.0/5247.0, 49.0/176.0, -5103.0/18656.0],
    [35.0/384.0, 0.0, 500.0/1113.0, 125.0/192.0, -2187.0/6784.0, 11.0/84.0]
]

# e_sol = b_sol - b_star
e_sol = [
    35.0/384.0 - 5179.0/57600.0,
    0.0,
    500.0/1113.0 - 7571.0/16695.0,
    125.0/192.0 - 393.0/640.0,
    -2187.0/6784.0 - (-92097.0/339200.0),
    11.0/84.0 - 187.0/2100.0,
    -1.0/40.0
]

def rk4_step(func, t, y, dt):
    """
    Pure PyTorch implementation of the Runge-Kutta 4th Order (RK4) step.
    """
    k1 = func(t, y)
    k2 = func(t + 0.5 * dt, y + 0.5 * dt * k1)
    k3 = func(t + 0.5 * dt, y + 0.5 * dt * k2)
    k4 = func(t + dt, y + dt * k3)
    
    y_new = y + (dt / 6.0) * (k1 + 2 * k2 + 2 * k3 + k4)
    
    return y_new

def dopri5_step(func, t, y, dt, k1=None):
    """
    One step of Dormand-Prince order 5(4).
    """
    if k1 is None:
        k1 = func(t, y)
    
    k2 = func(t + alpha[1] * dt, y + dt * (beta[1][0] * k1))
    k3 = func(t + alpha[2] * dt, y + dt * (beta[2][0] * k1 + beta[2][1] * k2))
    k4 = func(t + alpha[3] * dt, y + dt * (beta[3][0] * k1 + beta[3][1] * k2 + beta[3][2] * k3))
    k5 = func(t + alpha[4] * dt, y + dt * (beta[4][0] * k1 + beta[4][1] * k2 + beta[4][2] * k3 + beta[4][3] * k4))
    k6 = func(t + alpha[5] * dt, y + dt * (beta[5][0] * k1 + beta[5][1] * k2 + beta[5][2] * k3 + beta[5][3] * k4 + beta[5][4] * k5))
    
    y_next = y + dt * (beta[6][0] * k1 + beta[6][2] * k3 + beta[6][3] * k4 + beta[6][4] * k5 + beta[6][5] * k6)
    
    k7 = func(t + dt, y_next)
    
    y_err = dt * (e_sol[0] * k1 + e_sol[2] * k3 + e_sol[3] * k4 + e_sol[4] * k5 + e_sol[5] * k6 + e_sol[6] * k7)
    
    return y_next, y_err, k7

def select_initial_step(func, t0, y0, rtol, atol):
    """
    Select an initial step size dynamically.
    """
    order = 5
    f0 = func(t0, y0)
    scale = atol + torch.abs(y0) * rtol
    
    d0 = torch.sqrt(torch.mean((y0 / scale) ** 2))
    d1 = torch.sqrt(torch.mean((f0 / scale) ** 2))
    
    if d0 < 1e-5 or d1 < 1e-5:
        h0 = torch.tensor(1e-6, device=y0.device, dtype=y0.dtype)
    else:
        h0 = 0.01 * (d0 / d1)
        
    y1 = y0 + h0 * f0
    f1 = func(t0 + h0, y1)
    
    d2 = torch.sqrt(torch.mean(((f1 - f0) / scale) ** 2)) / h0
    
    if d1 <= 1e-15 and d2 <= 1e-15:
        h1 = torch.max(torch.tensor(1e-6, device=y0.device, dtype=y0.dtype), h0 * 1e-3)
    else:
        h1 = (0.01 / torch.max(d1, d2)) ** (1.0 / (order + 1))
        
    h = torch.min(100.0 * h0, h1)
    return h

def odeint(func, y0, t, rtol=None, atol=None):
    """
    Ordinary Differential Equation (ODE) solver in Pure PyTorch.
    Solves dy/dt = func(t, y) using fixed-step RK4 if both rtol and atol are None,
    otherwise uses adaptive step Dormand-Prince 5(4) (Dopri5).
    """
    if rtol is None and atol is None:
        # Fall back to the existing fixed-step RK4 solver
        solution = [y0]
        y = y0
        for i in range(len(t) - 1):
            t0 = t[i]
            t1 = t[i+1]
            dt = t1 - t0
            y = rk4_step(func, t0, y, dt)
            solution.append(y)
        return torch.stack(solution)
        
    # Standardize parameters if only one of them is None
    if rtol is None:
        rtol = 1e-6
    if atol is None:
        atol = 1e-9
        
    solution = [y0]
    y = y0
    
    # Initialize step size and initial derivative
    t0 = t[0]
    dt = select_initial_step(func, t0, y, rtol, atol)
    k1 = func(t0, y)
    
    for i in range(len(t) - 1):
        t_start = t[i]
        t_end = t[i+1]
        
        current_t = t_start.clone()
        direction = 1.0 if t_end >= t_start else -1.0
        
        while (current_t < t_end if direction > 0 else current_t > t_end):
            # Clip step size to avoid overshooting the target t_end
            if direction > 0:
                dt_step = torch.min(dt, t_end - current_t)
            else:
                dt_step = torch.max(-dt, t_end - current_t)
                
            y_next, y_err, k7 = dopri5_step(func, current_t, y, dt_step, k1)
            
            # Compute scaling error
            scale = atol + torch.maximum(torch.abs(y), torch.abs(y_next)) * rtol
            error_ratio = torch.sqrt(torch.mean((y_err / scale) ** 2))
            error_ratio = torch.max(error_ratio, torch.tensor(1e-10, device=y.device, dtype=y.dtype))
            
            # Step size adaptation logic
            if error_ratio <= 1.0:
                # Accept step
                current_t = current_t + dt_step
                y = y_next
                k1 = k7
                
                factor = 0.9 * (error_ratio ** -0.2)
                factor = torch.clamp(factor, min=0.2, max=10.0)
                dt = dt * factor
            else:
                # Reject step: shrink step size and retry
                factor = 0.9 * (error_ratio ** -0.2)
                factor = torch.clamp(factor, min=0.2, max=0.9)
                dt = dt * factor
                
        solution.append(y)
        
    return torch.stack(solution)

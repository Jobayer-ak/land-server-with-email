import { NextFunction, Request, Response } from 'express';

export const requireAdmin = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const userRole = (req as any).user?.userRole;

  if (userRole !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Admin privileges required.',
    });
  }

  next();
};

export const requireModerator = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const userRole = (req as any).user?.userRole;

  if (userRole !== 'admin' && userRole !== 'moderator') {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Moderator or admin privileges required.',
    });
  }

  next();
};

export const requireRole = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = (req as any).user?.userRole;

    if (!userRole || !roles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required roles: ${roles.join(', ')}`,
      });
    }

    next();
  };
};

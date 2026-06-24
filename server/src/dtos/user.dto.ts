export class UserDTO {
  static toResponse(user: any) {
    if (!user) return null;
    return {
      id: user._id || user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      avatarUrl: user.avatarUrl,
      role: user.role,
      status: user.status,
      createdAt: user.createdAt,
    };
  }

  static toResponseList(users: any[]) {
    if (!users) return [];
    return users.map(u => this.toResponse(u));
  }
}

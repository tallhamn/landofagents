// Safe floor — all agents can read local files
permit(
  principal,
  action == Action::"fs:Read",
  resource
);

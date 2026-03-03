export type PendingActionStatus = "pending" | "approved" | "denied" | "expired";

export type PendingAction = {
  id: string;
  tool: string;
  params: Record<string, unknown>;
  nonce: string;
  createdAt: number;
  expiresAt: number;
  status: PendingActionStatus;
  sessionId?: string;
  authorizedUserId?: string;
};

export class PendingActionStore {
  private actions = new Map<string, PendingAction>();

  add(action: PendingAction): void {
    this.actions.set(action.id, action);
  }

  get(id: string): PendingAction | undefined {
    return this.actions.get(id);
  }

  resolve(id: string, status: "approved" | "denied"): void {
    this.actions.delete(id);
  }

  expire(id: string): void {
    const action = this.actions.get(id);
    if (action) {
      action.status = "expired";
      this.actions.delete(id);
    }
  }

  getExpired(): PendingAction[] {
    const now = Date.now();
    const expired: PendingAction[] = [];
    for (const action of this.actions.values()) {
      if (action.expiresAt < now) {
        expired.push(action);
      }
    }
    return expired;
  }

  listByTool(tool: string): PendingAction[] {
    return Array.from(this.actions.values()).filter((a) => a.tool === tool);
  }

  clear(): void {
    this.actions.clear();
  }

  getAll(): PendingAction[] {
    return Array.from(this.actions.values());
  }
}

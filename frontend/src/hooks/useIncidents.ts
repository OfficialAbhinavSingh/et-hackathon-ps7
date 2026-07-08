/**
 * React binding to the DataService seam. Subscribes once, keeps an ordered incident list and
 * connection state, and re-renders on every patch. All views read from this — no component
 * ever touches the service's transport directly.
 */
import { useEffect, useState, useSyncExternalStore, useCallback } from "react";
import { dataService } from "../data";
import type { IncidentView, ConnectionState, Metrics } from "../types/contracts";

let started = false;

/** Subscribe to the live incident stream. Returns newest-first incidents + connection state. */
export function useIncidents() {
  const [incidents, setIncidents] = useState<IncidentView[]>(() => dataService.getIncidents());
  const [connection, setConnection] = useState<ConnectionState>("offline");

  useEffect(() => {
    if (!started) {
      started = true;
      dataService.start();
    }
    const unsub = dataService.subscribeIncidents(
      () => setIncidents(dataService.getIncidents()),
      (state) => setConnection(state),
    );
    // sync any incidents that arrived before this subscription
    setIncidents(dataService.getIncidents());
    return unsub;
  }, []);

  return { incidents, connection };
}

/** Live metrics, recomputed whenever the stream patches. */
export function useMetrics(): Metrics {
  const subscribe = useCallback((cb: () => void) => {
    const unsub = dataService.subscribeIncidents(() => cb());
    return unsub;
  }, []);
  // getMetrics returns a fresh object each call; cache by JSON so useSyncExternalStore is stable
  const getSnapshot = useCallback(() => JSON.stringify(dataService.getMetrics()), []);
  const raw = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  return JSON.parse(raw) as Metrics;
}

export { dataService };

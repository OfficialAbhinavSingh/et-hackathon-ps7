/**
 * The single swap point. VITE_DATA_SOURCE=mock|live selects the implementation.
 * Components import `dataService` from here and never know which impl backs it.
 * Default is "mock" so the dashboard runs standalone before the backend (#11) exists.
 */
import type { DataService } from "./DataService";
import { MockDataService } from "./mock/MockDataService";
import { HttpDataService } from "./http/HttpDataService";

const source = (import.meta.env.VITE_DATA_SOURCE as string | undefined) ?? "mock";
const baseUrl = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

export const dataService: DataService =
  source === "live" ? new HttpDataService(baseUrl) : new MockDataService();

export const DATA_SOURCE = source;

export * from "./DataService";

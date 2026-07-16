-- Last Xray user activity (unix seconds) for panel online presence.
-- Updated when traffic recorder sees a non-zero Xray counter delta (or online stats).
ALTER TABLE traffic_xray_snapshot ADD COLUMN last_activity_at INTEGER;

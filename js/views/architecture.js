/* Warden View Module - Architecture Visualizer */

import { ArchVisualizer } from '../arch-visualizer.js';

export function initArchitecture() {
  const archSvg = document.getElementById("arch-svg-container");
  const archList = document.getElementById("arch-layer-list");
  const archInfo = document.getElementById("arch-info-box");

  if (archSvg && archList && archInfo) {
    const archVis = new ArchVisualizer(archSvg, archList, archInfo);
    archVis.init();
    return archVis;
  }
  return null;
}

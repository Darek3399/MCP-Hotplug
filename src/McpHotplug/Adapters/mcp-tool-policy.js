'use strict';

const DISCOVERY_SCHEMA_VERSION = 5;

const HOTPLUG_CONTROL_SERVER_ID = 'hotplug_control';
const HOTPLUG_CONTROL_MANAGE_TOOL = 'manage_tools';
const HOTPLUG_CONTROL_LIST_TOOL = 'list_tools';

const DISABLED_TOOLS_NOTE_USER_ONLY =
  'Tools or categories listed under disabled_tools (name-only, without description or inputSchema) are currently disabled by the user in MCP Hotplug to save tokens. Do not call them directly; if you need one, ask the user to enable it.';

const DISABLED_TOOLS_NOTE_SELF_MANAGE =
  'disabled_tools lists hidden capabilities (name-only) disabled in MCP Hotplug to save tokens. Do not call them directly. ' +
  'To trim unused servers/categories/tools for a task or enable a missing disabled tool, batch all changes in ONE call via ' +
  'hotplug_control::manage_tools (call hotplug_control::list_tools first only if you need exact full names). ' +
  'Avoid frequent piecemeal toggling to save per-turn tool-call limits.';

const DISABLED_TOOLS_NOTE = DISABLED_TOOLS_NOTE_USER_ONLY;

const GATEWAY_ALL_TOOLS_DESCRIPTION =
  'Returns the latest per-server tool catalog snapshot published by the independent MCP Poll Manager. ' +
  'This operation reads the cache only: it does not probe, initialize, or wait for any upstream server. ' +
  'The catalog includes stable tool_id values, complete inputSchema JSON Schemas, source server information, ' +
  'per-server status, staleness, catalog_revision, compact name-only disabled_tools lists, and disabled_tools_note explaining how to handle disabled capabilities.';

function getDisabledToolsNote(canSelfManage = false) {
  return canSelfManage ? DISABLED_TOOLS_NOTE_SELF_MANAGE : DISABLED_TOOLS_NOTE_USER_ONLY;
}

function formatToolDisabledMessage(targetLabel, serverName = null, canSelfManage = false) {
  const location = serverName ? (' on server "' + serverName + '"') : '';
  const action = canSelfManage
    ? 'Enable it via hotplug_control::manage_tools (batch changes in one call) if needed.'
    : 'Ask the user to enable it in MCP Hotplug if this operation is needed.';
  return 'Tool "' + targetLabel + '"' + location + ' is currently disabled in MCP Hotplug to save tokens. ' + action;
}

function formatDisabledToolsetsFooter(disabledNames, canSelfManage = false) {
  const hint = canSelfManage
    ? 'Use hotplug_control::manage_tools to enable if needed.'
    : 'Ask the user to enable in MCP Hotplug if needed.';
  return '\n\n[Disabled toolsets in MCP Hotplug: ' + disabledNames.join(', ') + '. ' + hint + ']';
}

const ACTION_PARAM_NAMES = ['action', 'command', 'operation', 'subcommand', 'sub_action'];
const TOOLSET_ROOT_SEGMENT = '__toolsets__';
const HOTPLUG_ROOT_SEGMENT = '__hotplug__';

const SKIP_TRAVERSE_KEYS = new Set([
  'inputSchema', 'input_schema', 'outputSchema', 'output_schema',
  'parameters', 'annotations', '_meta', 'disabled_tools', 'disabled_tools_note',
  'disabled_toolsets', '$schema', 'examples', 'errors', 'error', 'warnings', 'warning'
]);

const ANONYMOUS_WRAPPER_HINTS = new Set([
  'result', 'data', 'payload', 'response', 'categories', 'subcategories',
  'groups', 'children', 'items', 'entries', 'list', 'tools', 'toolsets', 'servers'
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isValidInputSchema(schema) {
  if (!isPlainObject(schema)) return false;
  if (schema.type !== undefined && typeof schema.type !== 'string' && !Array.isArray(schema.type)) return false;
  if (schema.properties !== undefined && !isPlainObject(schema.properties)) return false;
  return true;
}

function isExecutableTool(tool) {
  if (!isPlainObject(tool)) return false;
  if (typeof tool.name !== 'string' || !tool.name.trim()) return false;
  if (tool.inputSchema !== undefined && !isValidInputSchema(tool.inputSchema)) return false;
  return true;
}

function cloneJson(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function encodeSegment(segment) {
  return String(segment || '').replace(/%/g, '%25').replace(/\//g, '%2F');
}

function decodeSegment(segment) {
  return String(segment || '').replace(/%2F/gi, '/').replace(/%25/g, '%');
}

function joinPath(segments) {
  return segments.map(encodeSegment).join('/');
}

function splitPath(nodePath) {
  return String(nodePath || '').split('/').filter(Boolean).map(decodeSegment);
}

function normalizeDisabledList(list) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const result = [];
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result.sort();
}

function createDisabledSet(disabledList) {
  return new Set(normalizeDisabledList(disabledList));
}

function isPathDisabled(nodePath, disabledSet) {
  if (!disabledSet || disabledSet.size === 0) return false;
  if (disabledSet.has('*') || disabledSet.has(nodePath)) return true;
  const parts = String(nodePath || '').split('/').filter(Boolean);
  let prefix = '';
  for (let i = 0; i < parts.length - 1; i++) {
    prefix = i === 0 ? parts[i] : (prefix + '/' + parts[i]);
    if (disabledSet.has(prefix)) return true;
  }
  return false;
}

function normalizeStringOrArray(value) {
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  if (Array.isArray(value)) {
    return value.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim());
  }
  return [];
}

function extractSchemaSubActions(tool) {
  const schema = isPlainObject(tool && tool.inputSchema) ? tool.inputSchema : null;
  if (!schema) return null;

  const props = isPlainObject(schema.properties) ? schema.properties : null;
  if (props) {
    for (const paramName of ACTION_PARAM_NAMES) {
      const prop = props[paramName];
      if (!isPlainObject(prop)) continue;
      if (Array.isArray(prop.enum) && prop.enum.length >= 2 && prop.enum.every(v => typeof v === 'string' && v.trim())) {
        return {
          mode: 'enum',
          paramName,
          actions: [...new Set(prop.enum.map(v => String(v)))]
        };
      }
    }
  }

  for (const unionKey of ['oneOf', 'anyOf']) {
    const branches = schema[unionKey];
    if (!Array.isArray(branches) || branches.length < 2) continue;
    for (const paramName of ACTION_PARAM_NAMES) {
      const actions = [];
      let allMatch = true;
      for (const branch of branches) {
        const bProps = isPlainObject(branch && branch.properties) ? branch.properties : null;
        const p = bProps && isPlainObject(bProps[paramName]) ? bProps[paramName] : null;
        if (p && typeof p.const === 'string' && p.const.trim()) {
          actions.push(p.const);
        } else if (p && Array.isArray(p.enum) && p.enum.length === 1 && typeof p.enum[0] === 'string') {
          actions.push(p.enum[0]);
        } else {
          allMatch = false;
          break;
        }
      }
      if (allMatch && actions.length >= 2) {
        return { mode: unionKey, paramName, actions: [...new Set(actions)] };
      }
    }
  }

  return null;
}

// ----------------------------------------------------------------------------
// JSON Schema introspection (Draft 2020-12 & Pydantic v2 anyOf/oneOf nullable)
// ----------------------------------------------------------------------------
function unwrapNullableSchema(prop) {
  if (!isPlainObject(prop)) return prop;
  for (const unionKey of ['anyOf', 'oneOf']) {
    if (Array.isArray(prop[unionKey]) && prop[unionKey].length > 0) {
      const nonNull = prop[unionKey].filter(b => isPlainObject(b) && b.type !== 'null');
      if (nonNull.length === 1) {
        return unwrapNullableSchema(nonNull[0]);
      }
    }
  }
  if (Array.isArray(prop.type)) {
    const nonNullTypes = prop.type.filter(t => t !== 'null');
    if (nonNullTypes.length === 1) {
      return { ...prop, type: nonNullTypes[0] };
    }
  }
  return prop;
}

function getSchemaProps(tool) {
  const s = isPlainObject(tool && tool.inputSchema) ? tool.inputSchema : null;
  return s && isPlainObject(s.properties) ? s.properties : {};
}

function getSchemaRequired(tool) {
  const s = isPlainObject(tool && tool.inputSchema) ? tool.inputSchema : null;
  return s && Array.isArray(s.required) ? s.required.filter(x => typeof x === 'string') : [];
}

function getPropTypes(rawProp) {
  const u = unwrapNullableSchema(rawProp);
  if (!isPlainObject(u) || u.type === undefined) return [];
  return Array.isArray(u.type) ? u.type : [u.type];
}

function isOpenObjectSchema(rawProp) {
  const prop = unwrapNullableSchema(rawProp);
  if (!isPlainObject(prop)) return false;
  if (!getPropTypes(prop).includes('object')) return false;
  const hasExplicitProps = isPlainObject(prop.properties) && Object.keys(prop.properties).length > 0;
  if (hasExplicitProps) return false;
  if (prop.additionalProperties === false) return false;
  return true;
}

function isFreeStringSchema(rawProp) {
  const prop = unwrapNullableSchema(rawProp);
  if (!isPlainObject(prop)) return false;
  if (!getPropTypes(prop).includes('string')) return false;
  if (Array.isArray(prop.enum) && prop.enum.length > 0) return false;
  if (prop.const !== undefined) return false;
  return true;
}

function isStringArraySchema(rawProp) {
  const prop = unwrapNullableSchema(rawProp);
  if (!isPlainObject(prop)) return false;
  if (!getPropTypes(prop).includes('array')) return false;
  return isFreeStringSchema(prop.items);
}

function isSimpleScalarSchema(rawProp) {
  const prop = unwrapNullableSchema(rawProp);
  if (!isPlainObject(prop)) return false;
  const types = getPropTypes(prop);
  return types.some(t => ['boolean', 'string', 'integer', 'number'].includes(t));
}

function isReadOnlyTool(tool) {
  return Boolean(tool && isPlainObject(tool.annotations) && tool.annotations.readOnlyHint === true);
}

function isNonMutatingCandidate(tool) {
  const a = tool && isPlainObject(tool.annotations) ? tool.annotations : null;
  if (!a) return true;
  if (a.destructiveHint === true) return false;
  if (a.readOnlyHint === false) return false;
  return true;
}

// ----------------------------------------------------------------------------
// Universal schema-driven meta-MCP role detection (zero hardcoded tool names)
// ----------------------------------------------------------------------------
function detectMetaPattern(tools) {
  const safeTools = Array.isArray(tools)
    ? tools.filter(t => isPlainObject(t) && typeof t.name === 'string' && t.name.trim())
    : [];
  if (safeTools.length < 2) return null;

  // Step A: Find proxy dispatcher (executor) by invariant schema signature:
  // - Prefer tools without readOnlyHint: true, with fallback to readOnlyHint: true
  //   only when no non-read-only dispatcher matches (e.g. nested MCP Hotplug gateway).
  // - Exactly 1 open-object parameter (arbitrary argument bag)
  // - At least 1 required free-string parameter (target tool identifier)
  // - Remaining parameters are free strings or optional simple scalars
  function matchDispatcher(t) {
    const props = getSchemaProps(t);
    const entries = Object.entries(props);
    if (entries.length < 2 || entries.length > 8) return null;

    const reqSet = new Set(getSchemaRequired(t));
    const openObjParams = [];
    const stringParams = [];

    for (const [k, prop] of entries) {
      if (isOpenObjectSchema(prop)) {
        openObjParams.push(k);
      } else if (isFreeStringSchema(prop)) {
        stringParams.push({ name: k, required: reqSet.has(k) });
      } else if (!reqSet.has(k) && isSimpleScalarSchema(prop)) {
        // Optional scalar knobs (e.g. timeout, dry_run, format) are permitted.
      } else {
        return null;
      }
    }

    if (openObjParams.length !== 1 || stringParams.length === 0) return null;
    if (!stringParams.some(p => p.required)) return null;

    const requiredStrings = stringParams.filter(p => p.required).map(p => p.name);
    const optionalStrings = stringParams.filter(p => !p.required).map(p => p.name);
    return {
      name: t.name,
      argsParam: openObjParams[0],
      stringParams,
      toolParam: requiredStrings[0],
      groupParam: optionalStrings[0] || (requiredStrings.length >= 2 ? requiredStrings[1] : null)
    };
  }

  const dispatchers = [];
  for (const t of safeTools) {
    if (isReadOnlyTool(t)) continue;
    const matched = matchDispatcher(t);
    if (matched) dispatchers.push(matched);
  }
  if (dispatchers.length === 0) {
    for (const t of safeTools) {
      if (!isReadOnlyTool(t)) continue;
      const matched = matchDispatcher(t);
      if (matched) dispatchers.push(matched);
    }
  }

  if (dispatchers.length === 0) return null;
  const dispatcher = dispatchers[0];

  // Step B: Find 0-required-param lister candidates
  const listers = [];
  for (const t of safeTools) {
    if (t.name === dispatcher.name) continue;
    if (!isNonMutatingCandidate(t)) continue;
    if (getSchemaRequired(t).length !== 0) continue;
    const propEntries = Object.entries(getSchemaProps(t));
    if (propEntries.length > 3) continue;
    if (propEntries.some(([, p]) => isOpenObjectSchema(p) || !isSimpleScalarSchema(p))) continue;
    listers.push({
      name: t.name,
      propCount: propEntries.length,
      readOnly: isReadOnlyTool(t)
    });
  }
  listers.sort((a, b) => (a.propCount - b.propCount) || (b.readOnly - a.readOnly));

  // Step C: Find 1-required-param inspector / search candidates (string or string[])
  const inspectors = [];
  for (const t of safeTools) {
    if (t.name === dispatcher.name) continue;
    if (!isNonMutatingCandidate(t)) continue;
    const req = getSchemaRequired(t);
    if (req.length !== 1) continue;
    const props = getSchemaProps(t);
    const targetName = req[0];
    const targetProp = props[targetName];
    const isArray = isStringArraySchema(targetProp);
    const isScalar = isFreeStringSchema(targetProp);
    if (!isArray && !isScalar) continue;

    const optionalParams = [];
    let ok = true;
    for (const [k, p] of Object.entries(props)) {
      if (k === targetName) continue;
      if (isOpenObjectSchema(p) || !isSimpleScalarSchema(p)) {
        ok = false;
        break;
      }
      optionalParams.push({ name: k, types: getPropTypes(p) });
    }
    if (!ok) continue;

    inspectors.push({
      name: t.name,
      targetParam: targetName,
      isArray,
      optionalParams,
      hasBooleanOption: optionalParams.some(p => p.types.includes('boolean')),
      hasIntegerOption: optionalParams.some(p => p.types.includes('integer') || p.types.includes('number')),
      readOnly: isReadOnlyTool(t)
    });
  }

  inspectors.sort((a, b) => (b.hasBooleanOption - a.hasBooleanOption) || (b.readOnly - a.readOnly));

  if (listers.length === 0 && inspectors.length === 0) return null;

  const metaTools = new Set([
    dispatcher.name,
    ...listers.map(l => l.name),
    ...inspectors.map(i => i.name)
  ]);

  return {
    type: listers.length === 0 ? 'search' : (inspectors.length > 0 ? 'hierarchical' : 'catalog'),
    dispatcher,
    lister: listers[0] || null,
    listerCandidates: listers,
    inspectors,
    metaTools
  };
}

function resolveEffectiveMeta(discoveredNested, metaPattern) {
  if (isPlainObject(discoveredNested) && isPlainObject(discoveredNested.meta)) {
    const m = discoveredNested.meta;
    const metaTools = new Set(Array.isArray(m.metaTools) ? m.metaTools.filter(Boolean) : []);
    return {
      lister: typeof m.lister === 'string' && m.lister ? m.lister : null,
      dispatcher: isPlainObject(m.dispatcher) ? m.dispatcher : (metaPattern ? metaPattern.dispatcher : null),
      groupInspector: isPlainObject(m.groupInspector) ? m.groupInspector : null,
      leafInspector: isPlainObject(m.leafInspector) ? m.leafInspector : null,
      searchTool: isPlainObject(m.searchTool) ? m.searchTool : null,
      metaTools
    };
  }

  // Backward compatibility with cached schemaVersion <= 4 trees (before reconnect upgrades to v5)
  if (metaPattern) {
    const legacyGroup = metaPattern.inspectors && metaPattern.inspectors.length > 0
      ? metaPattern.inspectors[0]
      : null;
    const legacyLeaf = metaPattern.inspectors && metaPattern.inspectors.length > 1
      ? metaPattern.inspectors[1]
      : null;
    return {
      lister: metaPattern.lister ? metaPattern.lister.name : null,
      dispatcher: metaPattern.dispatcher,
      groupInspector: legacyGroup,
      leafInspector: legacyLeaf,
      searchTool: null,
      metaTools: metaPattern.metaTools
    };
  }

  return null;
}

function buildLeafOrSchemaNode(tool, parentSegments, disabledSet, leafMetaType) {
  const name = String(tool.name || '');
  const segments = [...parentSegments, name];
  const nodePath = joinPath(segments);
  const subActions = extractSchemaSubActions(tool);

  if (subActions && subActions.actions.length >= 2) {
    const children = subActions.actions.map(actionName => {
      const actionPath = joinPath([...segments, actionName]);
      return {
        path: actionPath,
        name: actionName,
        displayName: actionName,
        kind: 'tool',
        metaType: 'schema_action',
        description: '',
        enabled: !isPathDisabled(actionPath, disabledSet),
        indeterminate: false,
        children: []
      };
    });
    return finalizeCategoryNode({
      path: nodePath,
      name,
      displayName: name + ' (' + subActions.paramName + ')',
      kind: 'category',
      metaType: 'schema_root',
      description: String(tool.description || ''),
      paramName: subActions.paramName,
      children
    }, disabledSet);
  }

  return {
    path: nodePath,
    name,
    displayName: name,
    kind: 'tool',
    metaType: leafMetaType,
    description: String(tool.description || ''),
    enabled: !isPathDisabled(nodePath, disabledSet),
    indeterminate: false,
    children: []
  };
}

function finalizeCategoryNode(node, disabledSet) {
  const children = Array.isArray(node.children) ? node.children : [];
  if (children.length === 0) {
    const disabled = isPathDisabled(node.path, disabledSet);
    node.enabled = !disabled;
    node.indeterminate = false;
    node.totalLeafCount = 0;
    node.enabledLeafCount = 0;
    return node;
  }

  let totalLeaves = 0;
  let enabledLeaves = 0;
  for (const child of children) {
    if (child.kind === 'tool') {
      totalLeaves += 1;
      if (child.enabled) enabledLeaves += 1;
    } else {
      totalLeaves += Number(child.totalLeafCount || 0);
      enabledLeaves += Number(child.enabledLeafCount || 0);
    }
  }

  node.totalLeafCount = totalLeaves;
  node.enabledLeafCount = enabledLeaves;

  if (totalLeaves === 0) {
    node.enabled = !isPathDisabled(node.path, disabledSet);
    node.indeterminate = false;
  } else if (enabledLeaves === 0) {
    node.enabled = false;
    node.indeterminate = false;
  } else if (enabledLeaves === totalLeaves) {
    node.enabled = true;
    node.indeterminate = false;
  } else {
    node.enabled = false;
    node.indeterminate = true;
  }

  return node;
}

function buildNestedDiscoveredNodes(discovered, parentSegments, disabledSet) {
  if (!isPlainObject(discovered)) return [];

  if (discovered.pattern === 'toolsets' && Array.isArray(discovered.toolsets)) {
    const rootSegments = [...parentSegments, TOOLSET_ROOT_SEGMENT];
    const toolsetNodes = discovered.toolsets.map(ts => {
      const tsName = String(ts.name || '');
      const tsSegments = [...rootSegments, tsName];
      if (ts.isSingleTool === true) {
        return buildLeafOrSchemaNode({
          name: tsName,
          description: String(ts.description || ''),
          inputSchema: isPlainObject(ts.inputSchema) ? ts.inputSchema : {}
        }, rootSegments, disabledSet, 'toolset_tool');
      }
      const tsTools = Array.isArray(ts.tools) ? ts.tools : [];
      const validTools = tsTools.filter(isExecutableTool);
      if (validTools.length === 0) return null;

      const rootBucket = { children: new Map(), leaves: [] };
      for (const t of validTools) {
        const subPath = Array.isArray(t.subPath)
          ? t.subPath.filter(s => typeof s === 'string' && s.trim() && s.trim() !== tsName)
          : [];
        let bucket = rootBucket;
        for (const seg of subPath) {
          if (!bucket.children.has(seg)) bucket.children.set(seg, { children: new Map(), leaves: [] });
          bucket = bucket.children.get(seg);
        }
        bucket.leaves.push(t);
      }

      function buildSubtreeFromBucket(bucket, currentSegments) {
        const nodes = [];
        for (const [subName, childBucket] of bucket.children.entries()) {
          const subSegments = [...currentSegments, subName];
          const subChildren = buildSubtreeFromBucket(childBucket, subSegments);
          if (subChildren.length === 0) continue;
          nodes.push(finalizeCategoryNode({
            path: joinPath(subSegments),
            name: subName,
            displayName: subName,
            kind: 'category',
            metaType: 'subcategory',
            description: '',
            children: subChildren
          }, disabledSet));
        }
        for (const t of bucket.leaves) {
          nodes.push(buildLeafOrSchemaNode(t, currentSegments, disabledSet, 'toolset_tool'));
        }
        nodes.sort((a, b) => {
          if (a.kind !== b.kind) return a.kind === 'category' ? -1 : 1;
          return a.displayName.localeCompare(b.displayName);
        });
        return nodes;
      }

      const childNodes = buildSubtreeFromBucket(rootBucket, tsSegments);
      if (childNodes.length === 0) return null;

      return finalizeCategoryNode({
        path: joinPath(tsSegments),
        name: tsName,
        displayName: tsName,
        kind: 'category',
        metaType: 'toolset',
        description: String(ts.description || ''),
        children: childNodes
      }, disabledSet);
    }).filter(Boolean).sort((a, b) => a.displayName.localeCompare(b.displayName));

    if (toolsetNodes.length === 0) return [];

    const metaLabel = isPlainObject(discovered.meta) && Array.isArray(discovered.meta.metaTools) && discovered.meta.metaTools.length > 0
      ? discovered.meta.metaTools.join(' / ')
      : 'list_toolsets / describe_toolset / call_tool';

    return [
      finalizeCategoryNode({
        path: joinPath(rootSegments),
        name: 'toolsets',
        displayName: 'Toolsets (' + metaLabel + ')',
        kind: 'category',
        metaType: 'toolset_root',
        description: 'Nested MCP toolsets discovered from this server.',
        children: toolsetNodes
      }, disabledSet)
    ];
  }

  if (discovered.pattern === 'hotplug' && Array.isArray(discovered.servers)) {
    const rootSegments = [...parentSegments, HOTPLUG_ROOT_SEGMENT];
    const serverNodes = discovered.servers.map(srv => {
      const srvId = String(srv.id || srv.name || 'server');
      const srvName = String(srv.name || srvId);
      const srvSegments = [...rootSegments, srvId];
      let children = [];
      if (srv.nested && isPlainObject(srv.nested) && srv.nested.pattern !== 'none') {
        children = buildNestedDiscoveredNodes(srv.nested, srvSegments, disabledSet);
      } else {
        const srvTools = Array.isArray(srv.tools) ? srv.tools : [];
        children = srvTools
          .filter(isExecutableTool)
          .map(t => buildLeafOrSchemaNode(t, srvSegments, disabledSet, 'hotplug_tool'))
          .sort((a, b) => a.name.localeCompare(b.name));
      }
      if (children.length === 0) return null;

      return finalizeCategoryNode({
        path: joinPath(srvSegments),
        name: srvId,
        displayName: srvName,
        kind: 'category',
        metaType: 'hotplug_server',
        description: '',
        children
      }, disabledSet);
    }).filter(Boolean).sort((a, b) => a.displayName.localeCompare(b.displayName));

    if (serverNodes.length === 0) return [];

    const metaLabel = isPlainObject(discovered.meta) && Array.isArray(discovered.meta.metaTools) && discovered.meta.metaTools.length > 0
      ? discovered.meta.metaTools.join(' / ')
      : 'all_tools / call_tool';

    return [
      finalizeCategoryNode({
        path: joinPath(rootSegments),
        name: 'hotplug',
        displayName: 'Hotplug Catalog (' + metaLabel + ')',
        kind: 'category',
        metaType: 'hotplug_root',
        description: 'Nested MCP catalog discovered from this server.',
        children: serverNodes
      }, disabledSet)
    ];
  }

  return [];
}

function buildServerToolTree(tools, discoveredNested, disabledList) {
  const safeTools = Array.isArray(tools) ? tools : [];
  const disabledSet = createDisabledSet(disabledList);
  const metaPattern = detectMetaPattern(safeTools);
  const nodes = [];

  const hasDiscoveredToolsetItems = Boolean(
    isPlainObject(discoveredNested) &&
    discoveredNested.pattern === 'toolsets' &&
    Array.isArray(discoveredNested.toolsets) &&
    discoveredNested.toolsets.length > 0
  );
  const hasDiscoveredHotplugItems = Boolean(
    isPlainObject(discoveredNested) &&
    discoveredNested.pattern === 'hotplug' &&
    Array.isArray(discoveredNested.servers) &&
    discoveredNested.servers.length > 0
  );
  const hasDiscoveredMeta = Boolean(metaPattern && (hasDiscoveredToolsetItems || hasDiscoveredHotplugItems));

  // If discovery already completed at the current schema version and confirmed no nested tools exist,
  // treat this server as flat so UI and cache never spin waiting for meta discovery.
  const discoverySettledEmpty = Boolean(
    isPlainObject(discoveredNested) &&
    discoveredNested.schemaVersion === DISCOVERY_SCHEMA_VERSION &&
    !hasDiscoveredMeta &&
    (discoveredNested.pattern === 'none' || discoveredNested.pattern === 'toolsets' || discoveredNested.pattern === 'hotplug')
  );

  const effectiveMeta = resolveEffectiveMeta(discoveredNested, metaPattern);

  if (hasDiscoveredMeta) {
    nodes.push(...buildNestedDiscoveredNodes(discoveredNested, [], disabledSet));
    const hiddenMetaTools = effectiveMeta ? effectiveMeta.metaTools : new Set();
    for (const tool of safeTools) {
      if (!tool || typeof tool.name !== 'string' || !tool.name.trim()) continue;
      if (hiddenMetaTools.has(tool.name)) continue;
      nodes.push(buildLeafOrSchemaNode(tool, [], disabledSet, 'flat'));
    }
  } else {
    for (const tool of safeTools) {
      if (!tool || typeof tool.name !== 'string' || !tool.name.trim()) continue;
      nodes.push(buildLeafOrSchemaNode(tool, [], disabledSet, 'flat'));
    }
  }

  nodes.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'category' ? -1 : 1;
    return a.displayName.localeCompare(b.displayName);
  });

  let totalLeafCount = 0;
  let enabledLeafCount = 0;
  for (const node of nodes) {
    if (node.kind === 'tool') {
      totalLeafCount += 1;
      if (node.enabled) enabledLeafCount += 1;
    } else {
      totalLeafCount += Number(node.totalLeafCount || 0);
      enabledLeafCount += Number(node.enabledLeafCount || 0);
    }
  }

  const allDisabled = (totalLeafCount > 0 && enabledLeafCount === 0) ||
    (disabledSet.has('*') && (nodes.length > 0 || safeTools.length > 0));

  const effectiveHasMetaPattern = Boolean(metaPattern) && !discoverySettledEmpty;
  const effectivePatternType = hasDiscoveredMeta
    ? discoveredNested.pattern
    : (effectiveHasMetaPattern ? metaPattern.type : null);

  return {
    nodes,
    totalLeafCount,
    enabledLeafCount,
    allDisabled,
    hasMetaPattern: effectiveHasMetaPattern,
    metaPatternType: effectivePatternType,
    hasDiscoveredMeta,
    discoveredAt: isPlainObject(discoveredNested) ? (discoveredNested.discoveredAt || null) : null
  };
}

// Variant B: Even when a parent category is disabled, emit the full nested
// name-only hierarchy underneath so the AI knows indirectly what capabilities exist.
function buildCompactDisabledHierarchy(tree) {
  function collect(node) {
    if (node.kind === 'tool') {
      return node.enabled ? null : node.name;
    }

    const childItems = [];
    for (const child of node.children || []) {
      const item = collect(child);
      if (item !== null) childItems.push(item);
    }

    if (childItems.length === 0) {
      return (!node.enabled && !node.indeterminate && (node.children || []).length === 0)
        ? node.name
        : null;
    }

    if (node.metaType === 'toolset_root' || node.metaType === 'hotplug_root') {
      return { __unwrap__: true, items: childItems };
    }

    return { [node.name]: childItems };
  }

  const output = [];
  for (const node of (tree && tree.nodes) || []) {
    const item = collect(node);
    if (item === null) continue;
    if (isPlainObject(item) && item.__unwrap__ === true) {
      output.push(...item.items);
    } else {
      output.push(item);
    }
  }
  return output;
}

function pruneSchemaForDisabledActions(tool, toolPath, disabledSet) {
  const subActions = extractSchemaSubActions(tool);
  if (!subActions) return tool;

  const allowedActions = subActions.actions.filter(action =>
    !isPathDisabled(joinPath([...splitPath(toolPath), action]), disabledSet)
  );
  if (allowedActions.length === subActions.actions.length) return tool;
  if (allowedActions.length === 0) return null;

  const copy = cloneJson(tool);
  if (subActions.mode === 'enum' && copy.inputSchema && copy.inputSchema.properties && copy.inputSchema.properties[subActions.paramName]) {
    copy.inputSchema.properties[subActions.paramName].enum = allowedActions;
  } else if ((subActions.mode === 'oneOf' || subActions.mode === 'anyOf') && copy.inputSchema && Array.isArray(copy.inputSchema[subActions.mode])) {
    const allowedSet = new Set(allowedActions);
    copy.inputSchema[subActions.mode] = copy.inputSchema[subActions.mode].filter(branch => {
      const p = branch && branch.properties && branch.properties[subActions.paramName];
      const val = p && (typeof p.const === 'string' ? p.const : (Array.isArray(p.enum) ? p.enum[0] : null));
      return !val || allowedSet.has(val);
    });
  }
  return copy;
}

function filterCatalogToolsForServer(tools, discoveredNested, disabledList) {
  const safeTools = Array.isArray(tools) ? tools : [];
  const disabledSet = createDisabledSet(disabledList);
  const tree = buildServerToolTree(safeTools, discoveredNested, disabledList);
  const disabledHierarchy = buildCompactDisabledHierarchy(tree);

  if (tree.allDisabled) {
    return {
      tools: [],
      disabledTools: disabledHierarchy,
      allDisabled: true,
      tree
    };
  }

  const metaPattern = detectMetaPattern(safeTools);
  const effectiveMeta = resolveEffectiveMeta(discoveredNested, metaPattern);
  const enabledTools = [];

  for (const rawTool of safeTools) {
    if (!rawTool || typeof rawTool.name !== 'string' || !rawTool.name.trim()) continue;
    const toolName = rawTool.name;

    if (tree.hasDiscoveredMeta && effectiveMeta && effectiveMeta.metaTools.has(toolName)) {
      const rootSeg = discoveredNested.pattern === 'hotplug' ? HOTPLUG_ROOT_SEGMENT : TOOLSET_ROOT_SEGMENT;
      const rootNode = tree.nodes.find(n => n.path === rootSeg);
      if (rootNode && !rootNode.enabled && !rootNode.indeterminate) {
        continue;
      }
      if (isPathDisabled(encodeSegment(toolName), disabledSet)) {
        continue;
      }
      enabledTools.push(rawTool);
      continue;
    }

    const toolPath = encodeSegment(toolName);
    if (isPathDisabled(toolPath, disabledSet)) continue;

    const pruned = pruneSchemaForDisabledActions(rawTool, toolPath, disabledSet);
    if (pruned) enabledTools.push(pruned);
  }

  return {
    tools: enabledTools,
    disabledTools: disabledHierarchy,
    allDisabled: enabledTools.length === 0 && safeTools.length > 0,
    tree
  };
}

function getToolsetToolSegments(tsName, toolObj) {
  const subPath = toolObj && Array.isArray(toolObj.subPath)
    ? toolObj.subPath.filter(s => typeof s === 'string' && s.trim() && s.trim() !== tsName)
    : [];
  return [TOOLSET_ROOT_SEGMENT, tsName, ...subPath, String(toolObj.name || '')];
}

function matchToolsetTools(tsObj, requestedTool) {
  const tsTools = tsObj && Array.isArray(tsObj.tools) ? tsObj.tools : [];
  const clean = String(requestedTool || '').trim();
  if (!clean) return [];
  const prefixed = tsObj && tsObj.name ? (tsObj.name + '.' + clean) : '';
  const suffix = '.' + clean;
  return tsTools.filter(t =>
    t && typeof t.name === 'string' &&
    (t.name === clean || (prefixed && t.name === prefixed) || t.name.endsWith(suffix))
  );
}

function isToolsetFullyDisabled(tsName, discoveredNested, disabledSet) {
  const tsPath = joinPath([TOOLSET_ROOT_SEGMENT, tsName]);
  if (isPathDisabled(tsPath, disabledSet)) return true;
  const tsObj = isPlainObject(discoveredNested) && Array.isArray(discoveredNested.toolsets)
    ? discoveredNested.toolsets.find(t => t && t.name === tsName)
    : null;
  const tsTools = tsObj && Array.isArray(tsObj.tools) ? tsObj.tools : [];
  return tsTools.length > 0 && tsTools.every(t =>
    isPathDisabled(joinPath(getToolsetToolSegments(tsName, t)), disabledSet)
  );
}

function resolveLeafMatches(requestedTool, requestedGroup, discoveredNested) {
  const toolsets = isPlainObject(discoveredNested) && Array.isArray(discoveredNested.toolsets)
    ? discoveredNested.toolsets
    : [];
  const matches = [];
  for (const ts of toolsets) {
    if (requestedGroup && ts.name !== requestedGroup) continue;
    if (ts.isSingleTool === true && ts.name === requestedTool) {
      matches.push({ tsName: ts.name, segments: [TOOLSET_ROOT_SEGMENT, ts.name] });
      continue;
    }
    for (const t of matchToolsetTools(ts, requestedTool)) {
      matches.push({ tsName: ts.name, segments: getToolsetToolSegments(ts.name, t) });
    }
  }
  return matches;
}

function isLeafToolDisabled(requestedTool, requestedGroup, discoveredNested, disabledSet, nestedArgs = null) {
  const isLeafOrActionDisabled = (segments) => {
    if (isPathDisabled(joinPath(segments), disabledSet)) return true;
    if (isPlainObject(nestedArgs)) {
      for (const actionParam of ACTION_PARAM_NAMES) {
        if (typeof nestedArgs[actionParam] === 'string' && nestedArgs[actionParam].trim()) {
          if (isPathDisabled(joinPath([...segments, nestedArgs[actionParam].trim()]), disabledSet)) {
            return true;
          }
        }
      }
    }
    return false;
  };

  const matches = resolveLeafMatches(requestedTool, requestedGroup, discoveredNested);
  if (matches.length === 0) {
    if (requestedGroup) {
      return isPathDisabled(joinPath([TOOLSET_ROOT_SEGMENT, requestedGroup]), disabledSet) ||
             isLeafOrActionDisabled([TOOLSET_ROOT_SEGMENT, requestedGroup, requestedTool]);
    }
    return false;
  }
  return matches.every(m => isLeafOrActionDisabled(m.segments));
}

function checkToolCallAllowed(toolName, args, tools, discoveredNested, disabledList, options = {}) {
  const safeTools = Array.isArray(tools) ? tools : [];
  const disabledSet = createDisabledSet(disabledList);
  const safeArgs = isPlainObject(args) ? args : {};
  const tree = buildServerToolTree(safeTools, discoveredNested, disabledList);
  const canSelfManage = Boolean(options && options.canSelfManage);
  const serverName = options && typeof options.serverName === 'string' ? options.serverName : null;

  const blocked = (targetLabel) => ({
    allowed: false,
    code: 'TOOL_DISABLED',
    message: formatToolDisabledMessage(targetLabel, serverName, canSelfManage)
  });

  if (tree.allDisabled || disabledSet.has('*')) {
    return blocked(toolName);
  }

  const topPath = encodeSegment(toolName);
  if (isPathDisabled(topPath, disabledSet)) {
    return blocked(toolName);
  }

  const metaPattern = detectMetaPattern(safeTools);
  const effectiveMeta = resolveEffectiveMeta(discoveredNested, metaPattern);

  if (tree.hasDiscoveredMeta && effectiveMeta && discoveredNested.pattern === 'toolsets') {
    if (isPathDisabled(TOOLSET_ROOT_SEGMENT, disabledSet) && effectiveMeta.metaTools.has(toolName)) {
      return blocked(toolName);
    }

    const rootNode = tree.nodes.find(n => n.path === TOOLSET_ROOT_SEGMENT);
    if (rootNode && !rootNode.enabled && !rootNode.indeterminate && effectiveMeta.metaTools.has(toolName)) {
      return blocked(toolName);
    }

    if (effectiveMeta.groupInspector && toolName === effectiveMeta.groupInspector.name) {
      const requested = normalizeStringOrArray(safeArgs[effectiveMeta.groupInspector.targetParam]);
      if (requested.length > 0 && requested.every(g => isToolsetFullyDisabled(g, discoveredNested, disabledSet))) {
        return blocked(requested.join(', '));
      }
    }

    if (effectiveMeta.leafInspector && toolName === effectiveMeta.leafInspector.name) {
      const requested = normalizeStringOrArray(safeArgs[effectiveMeta.leafInspector.targetParam]);
      if (requested.length > 0 && requested.every(t => isLeafToolDisabled(t, '', discoveredNested, disabledSet))) {
        return blocked(requested.join(', '));
      }
    }

    if (effectiveMeta.dispatcher && toolName === effectiveMeta.dispatcher.name) {
      const disp = effectiveMeta.dispatcher;
      const nestedArgs = disp.argsParam && isPlainObject(safeArgs[disp.argsParam]) ? safeArgs[disp.argsParam] : {};
      const toolsetsList = Array.isArray(discoveredNested.toolsets) ? discoveredNested.toolsets : [];
      const knownGroups = new Set(toolsetsList.map(t => t.name));

      const strVals = (Array.isArray(disp.stringParams) ? disp.stringParams : [])
        .map(sp => typeof safeArgs[sp.name] === 'string' ? safeArgs[sp.name].trim() : '')
        .filter(Boolean);

      let reqGroup = '';
      let reqTool = '';
      for (const v of strVals) {
        if (!reqGroup && knownGroups.has(v)) {
          const tsObj = toolsetsList.find(t => t.name === v);
          if (tsObj && tsObj.isSingleTool) reqTool = v;
          else reqGroup = v;
        } else if (!reqTool) {
          reqTool = v;
        }
      }
      if (!reqTool && disp.toolParam && typeof safeArgs[disp.toolParam] === 'string') {
        reqTool = safeArgs[disp.toolParam].trim();
      }

      if (reqGroup && isToolsetFullyDisabled(reqGroup, discoveredNested, disabledSet)) {
        return blocked(reqGroup + '/' + (reqTool || '*'));
      }
      if (reqTool && isLeafToolDisabled(reqTool, reqGroup, discoveredNested, disabledSet, nestedArgs)) {
        const label = reqGroup ? (reqGroup + '/' + reqTool) : reqTool;
        return blocked(label);
      }
    }
  }

  if (tree.hasDiscoveredMeta && effectiveMeta && discoveredNested.pattern === 'hotplug') {
    if (isPathDisabled(HOTPLUG_ROOT_SEGMENT, disabledSet) && effectiveMeta.metaTools.has(toolName)) {
      return blocked(toolName);
    }
    const rootNode = tree.nodes.find(n => n.path === HOTPLUG_ROOT_SEGMENT);
    if (rootNode && !rootNode.enabled && !rootNode.indeterminate && effectiveMeta.metaTools.has(toolName)) {
      return blocked(toolName);
    }
    if (effectiveMeta.dispatcher && toolName === effectiveMeta.dispatcher.name) {
      const rawTarget = safeArgs[effectiveMeta.dispatcher.toolParam];
      if (typeof rawTarget === 'string') {
        const sep = rawTarget.indexOf('::');
        if (sep > 0) {
          let srvId = rawTarget.slice(0, sep);
          let subTool = rawTarget.slice(sep + 2);
          try { srvId = decodeURIComponent(srvId); } catch (_) {}
          try { subTool = decodeURIComponent(subTool); } catch (_) {}
          const targetPath = joinPath([HOTPLUG_ROOT_SEGMENT, srvId, subTool]);
          if (isPathDisabled(targetPath, disabledSet)) {
            return blocked(srvId + '/' + subTool);
          }
        }
      }
    }
  }

  const matchedTool = safeTools.find(t => t && t.name === toolName);
  if (matchedTool) {
    const subActions = extractSchemaSubActions(matchedTool);
    if (subActions) {
      const val = safeArgs[subActions.paramName];
      if (typeof val === 'string' && val.trim()) {
        const actionPath = joinPath([toolName, val.trim()]);
        if (isPathDisabled(actionPath, disabledSet)) {
          return blocked(toolName + '/' + val.trim());
        }
      }
    }
  }

  return { allowed: true };
}

// ----------------------------------------------------------------------------
// Bottom-up structural JSON + Markdown extractor
// ----------------------------------------------------------------------------
function extractJsonFromToolResult(result) {
  if (!isPlainObject(result)) return null;
  if (result.structuredContent !== undefined && result.structuredContent !== null) {
    return { data: cloneJson(result.structuredContent), source: 'structuredContent' };
  }
  const content = Array.isArray(result.content) ? result.content : [];
  for (let i = 0; i < content.length; i++) {
    const block = content[i];
    if (!block || block.type !== 'text' || typeof block.text !== 'string') continue;
    let text = block.text.trim();
    if (!text) continue;
    const fence = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
    if (fence) text = fence[1].trim();
    try {
      return { data: JSON.parse(text), source: 'text', blockIndex: i };
    } catch (_) {}
  }
  return null;
}

function getRawTextFromResult(result) {
  if (!isPlainObject(result) || !Array.isArray(result.content)) return '';
  return result.content
    .filter(b => b && b.type === 'text')
    .map(b => String(b.text || ''))
    .join('\n');
}

function writeFilteredJsonToToolResult(originalResult, extracted, filteredData) {
  const copy = cloneJson(originalResult);
  const serialized = JSON.stringify(filteredData);
  if (copy.structuredContent !== undefined) {
    copy.structuredContent = filteredData;
  }
  if (Array.isArray(copy.content)) {
    const idx = typeof extracted.blockIndex === 'number'
      ? extracted.blockIndex
      : copy.content.findIndex(b => b && b.type === 'text');
    if (idx >= 0) {
      copy.content[idx] = { ...copy.content[idx], type: 'text', text: serialized };
    } else {
      copy.content.push({ type: 'text', text: serialized });
    }
  } else {
    copy.content = [{ type: 'text', text: serialized }];
  }
  return copy;
}

function getToolInputSchema(obj) {
  if (!isPlainObject(obj)) return null;
  for (const k of ['inputSchema', 'input_schema', 'parameters']) {
    const s = obj[k];
    if (!isPlainObject(s)) continue;
    if (!isValidInputSchema(s)) continue;
    return s;
  }
  return null;
}

function hasStrongLeafMarkers(obj) {
  if (getToolInputSchema(obj) !== null) return true;
  if (isPlainObject(obj.outputSchema) || isPlainObject(obj.output_schema)) return true;
  if (isPlainObject(obj.annotations)) return true;
  if (typeof obj.tool_id === 'string' && obj.tool_id.trim()) return true;
  return false;
}

function hasListCollectionProp(obj) {
  for (const [k, v] of Object.entries(obj)) {
    if (SKIP_TRAVERSE_KEYS.has(k)) continue;
    if (Array.isArray(v)) return true;
  }
  return false;
}

function extractLeavesBottomUp(data) {
  if (data === null || data === undefined) return [];

  function visit(node, keyFromParent, inArray, depth) {
    if (depth > 18 || node === null || node === undefined) return [];

    if (Array.isArray(node)) {
      const collected = [];
      for (const el of node) {
        if (isPlainObject(el) || Array.isArray(el)) {
          collected.push(...visit(el, null, true, depth + 1));
        }
      }
      if (keyFromParent && collected.length > 0) {
        const isWrapperHint = ANONYMOUS_WRAPPER_HINTS.has(keyFromParent);
        for (const leaf of collected) {
          const top = leaf.ancestors[0];
          const isSameAsLeaf = leaf.ancestors.length === 0 && leaf.name === keyFromParent;
          if (!isSameAsLeaf && (!top || top.name !== keyFromParent)) {
            leaf.ancestors.unshift({
              kind: 'group',
              name: keyFromParent,
              description: '',
              fromKey: true,
              isWrapperHint
            });
          }
        }
      }
      return collected;
    }

    if (!isPlainObject(node)) return [];

    // Count sibling array-of-objects properties so a single collection prop ("tools"/"ops")
    // does not pollute the ancestor path, while sibling categorized arrays ({ Math: [...], IO: [...] }) do.
    const arrayOfObjKeys = [];
    for (const [k, v] of Object.entries(node)) {
      if (SKIP_TRAVERSE_KEYS.has(k)) continue;
      if (Array.isArray(v) && v.some(isPlainObject)) arrayOfObjKeys.push(k);
    }

    // 1. Descend first (post-order)
    const descendantLeaves = [];
    for (const [k, v] of Object.entries(node)) {
      if (SKIP_TRAVERSE_KEYS.has(k)) continue;
      if (!v || typeof v !== 'object') continue;
      const suppressArrayKey = Array.isArray(v) && arrayOfObjKeys.length === 1;
      descendantLeaves.push(...visit(v, suppressArrayKey ? null : k, false, depth + 1));
    }

    // 2. Bottom-up: if no descendant leaves were found, check whether this node itself is a leaf tool
    if (descendantLeaves.length === 0) {
      const ownName = String(node.name || node.tool_name || node.id || '').trim();
      const fallbackKey = (keyFromParent && !ANONYMOUS_WRAPPER_HINTS.has(keyFromParent))
        ? String(keyFromParent).trim()
        : '';
      const leafName = ownName || fallbackKey;
      const strong = hasStrongLeafMarkers(node);
      const weak = inArray && Boolean(ownName) && typeof node.description === 'string' && !hasListCollectionProp(node);

      if (leafName && (strong || weak) && !hasListCollectionProp(node)) {
        const ancestors = [];
        if (isPlainObject(node.source) && typeof node.source.server_id === 'string' && node.source.server_id.trim()) {
          ancestors.push({
            kind: 'source',
            id: node.source.server_id.trim(),
            name: String(node.source.server_name || node.source.server_id).trim(),
            description: '',
            fromKey: false,
            isWrapperHint: false
          });
        }
        return [{
          name: leafName,
          description: String(node.description || ''),
          inputSchema: getToolInputSchema(node) || {},
          toolId: typeof node.tool_id === 'string' ? node.tool_id : null,
          ancestors
        }];
      }
      return [];
    }

    // 3. Bubble up: prepend this container's identity to all descendant leaves
    const ownName = String(node.name || node.toolset_name || node.id || '').trim();
    const keyName = keyFromParent ? String(keyFromParent).trim() : '';
    const containerName = ownName || keyName;
    const containerDesc = String(node.description || '');
    const fromKey = !ownName && Boolean(keyName);
    const isWrapperHint = fromKey && ANONYMOUS_WRAPPER_HINTS.has(keyName);

    if (containerName) {
      for (const leaf of descendantLeaves) {
        const top = leaf.ancestors[0];
        const isSameAsLeaf = leaf.ancestors.length === 0 && leaf.name === containerName;
        if (!isSameAsLeaf && (!top || top.name !== containerName)) {
          leaf.ancestors.unshift({
            kind: 'group',
            name: containerName,
            description: containerDesc,
            fromKey,
            isWrapperHint
          });
        } else if (top && top.name === containerName) {
          if (!top.description && containerDesc) top.description = containerDesc;
          if (!fromKey) {
            top.fromKey = false;
            top.isWrapperHint = false;
          }
        }
      }
    }

    return descendantLeaves;
  }

  return visit(data, null, false, 0);
}

function extractNameOnlyLeavesFallback(data, groupName = '') {
  let stringList = null;
  if (Array.isArray(data) && data.length > 0 && data.every(x => typeof x === 'string' && x.trim())) {
    stringList = data;
  } else if (isPlainObject(data)) {
    const arrayKeys = Object.entries(data)
      .filter(([k, v]) => !SKIP_TRAVERSE_KEYS.has(k) && Array.isArray(v) && v.length > 0 && v.every(x => typeof x === 'string' && x.trim()));
    if (arrayKeys.length === 1) {
      stringList = arrayKeys[0][1];
    }
  }
  if (!stringList) return [];
  const seen = new Set();
  const out = [];
  for (const raw of stringList) {
    const clean = raw.trim();
    if (!clean || seen.has(clean)) continue;
    seen.add(clean);
    const ancestors = groupName
      ? [{ kind: 'group', name: groupName, description: '', fromKey: false, isWrapperHint: false }]
      : [];
    out.push({ name: clean, description: '', inputSchema: {}, toolId: null, ancestors });
  }
  return out;
}

function extractLeavesFromMarkdown(rawText, groupName = '') {
  if (!rawText) return [];
  const leaves = [];
  const seen = new Set();
  const skipHeaders = new Set([
    'Tools', 'Toolset', 'Toolsets', 'Parameters', 'Description', 'Schema', 'Arguments', 'Returns', 'Examples'
  ]);
  for (const line of String(rawText).split(/\r?\n/)) {
    const m = line.match(/^\s*(?:[-*+]|\d+\.|#{2,4})\s+`?([A-Za-z0-9_.:-]+)`?(?:\s*\([^)]*\))?(?:\s*[:\-–—]\s*(.*))?$/);
    if (!m) continue;
    const name = m[1].trim();
    if (!name || skipHeaders.has(name) || seen.has(name)) continue;
    seen.add(name);
    const ancestors = groupName
      ? [{ kind: 'group', name: groupName, description: '', fromKey: false, isWrapperHint: false }]
      : [];
    leaves.push({ name, description: (m[2] || '').trim(), inputSchema: {}, toolId: null, ancestors });
  }
  return leaves;
}

function extractGroupCandidates(data, rawText) {
  const out = [];
  const seen = new Set();
  const add = (name, desc = '') => {
    const clean = String(name || '').trim();
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    out.push({ name: clean, description: String(desc || '') });
  };

  function walkArray(arr) {
    for (const item of arr) {
      if (typeof item === 'string') add(item, '');
      else if (isPlainObject(item)) {
        const n = item.name || item.toolset_name || item.toolset || item.group || item.id || item.title;
        if (n) add(n, item.description || item.summary || '');
      }
    }
  }

  if (Array.isArray(data)) {
    walkArray(data);
  } else if (isPlainObject(data)) {
    for (const [k, val] of Object.entries(data)) {
      if (SKIP_TRAVERSE_KEYS.has(k)) continue;
      if (Array.isArray(val)) {
        walkArray(val);
        if (out.length > 0) break;
      } else if (isPlainObject(val)) {
        for (const [subK, subV] of Object.entries(val)) {
          add(subK, isPlainObject(subV) ? (subV.description || '') : (typeof subV === 'string' ? subV : ''));
        }
        if (out.length > 0) break;
      }
    }
  }

  if (out.length === 0 && rawText) {
    for (const line of String(rawText).split(/\r?\n/)) {
      const m = line.match(/^\s{0,1}(?:[-*+]|\d+\.)\s+`?([A-Za-z0-9_.:-]+)`?(?:\s*[:\-–—]\s*(.*))?$/);
      if (m) add(m[1], m[2] || '');
    }
  }

  return out;
}

function groupLeavesIntoToolsets(leaves, candidateSet = new Set(), descByGroup = new Map()) {
  const byGroup = new Map();
  const ungrouped = [];

  for (const leaf of leaves) {
    let groupName = '';
    let groupDesc = '';
    let subPath = [];

    // Anchor to the ancestor matching a real lister candidate -> automatically peels any arbitrary root wrapper
    const anchorIdx = leaf.ancestors.findIndex(a => candidateSet.has(a.name));
    if (anchorIdx >= 0) {
      groupName = leaf.ancestors[anchorIdx].name;
      groupDesc = leaf.ancestors[anchorIdx].description || descByGroup.get(groupName) || '';
      subPath = leaf.ancestors
        .slice(anchorIdx + 1)
        .filter(a => !a.isWrapperHint && a.name !== groupName && a.name !== leaf.name)
        .map(a => a.name);
    } else {
      const meaningful = leaf.ancestors.filter(a => !a.isWrapperHint);
      if (meaningful.length > 0) {
        groupName = meaningful[0].name;
        groupDesc = meaningful[0].description || descByGroup.get(groupName) || '';
        subPath = meaningful.slice(1).map(a => a.name).filter(s => s && s !== groupName && s !== leaf.name);
      } else {
        ungrouped.push(leaf);
        continue;
      }
    }

    if (!byGroup.has(groupName)) {
      byGroup.set(groupName, { name: groupName, description: groupDesc, tools: [], seenTools: new Set() });
    }
    const entry = byGroup.get(groupName);
    if (!entry.description && groupDesc) entry.description = groupDesc;
    if (entry.seenTools.has(leaf.name)) continue;
    entry.seenTools.add(leaf.name);

    const toolObj = {
      name: leaf.name,
      description: leaf.description,
      inputSchema: leaf.inputSchema || {}
    };
    if (subPath.length > 0) toolObj.subPath = subPath;
    if (isExecutableTool(toolObj)) entry.tools.push(toolObj);
  }

  const toolsets = [...byGroup.values()]
    .filter(g => g.tools.length > 0)
    .map(g => {
      if (g.tools.length === 1 && g.tools[0].name === g.name) {
        return {
          name: g.name,
          description: g.tools[0].description || g.description,
          isSingleTool: true,
          inputSchema: g.tools[0].inputSchema || {},
          tools: []
        };
      }
      return { name: g.name, description: g.description, tools: g.tools };
    });

  const seenUngrouped = new Set();
  for (const leaf of ungrouped) {
    if (seenUngrouped.has(leaf.name)) continue;
    seenUngrouped.add(leaf.name);
    const single = {
      name: leaf.name,
      description: leaf.description,
      isSingleTool: true,
      inputSchema: leaf.inputSchema || {},
      tools: []
    };
    if (isExecutableTool(single)) toolsets.push(single);
  }

  return toolsets;
}

// ----------------------------------------------------------------------------
// Key-agnostic response filtering (JSON + Markdown)
// ----------------------------------------------------------------------------
function filterToolCallResponse(toolName, args, result, tools, discoveredNested, disabledList, options = {}) {
  if (!isPlainObject(result) || result.isError === true) return result;
  const safeTools = Array.isArray(tools) ? tools : [];
  const metaPattern = detectMetaPattern(safeTools);
  const effectiveMeta = resolveEffectiveMeta(discoveredNested, metaPattern);
  if (!effectiveMeta || !isPlainObject(discoveredNested) || discoveredNested.pattern === 'none') {
    return result;
  }

  const disabledSet = createDisabledSet(disabledList);
  if (disabledSet.size === 0) return result;

  const extracted = extractJsonFromToolResult(result);
  const canSelfManage = Boolean(options && options.canSelfManage);
  const disabledNote = getDisabledToolsNote(canSelfManage);

  // Hotplug catalog lister response filtering
  if (discoveredNested.pattern === 'hotplug' && effectiveMeta.lister && toolName === effectiveMeta.lister) {
    if (!extracted || !isPlainObject(extracted.data) || !Array.isArray(extracted.data.tools)) return result;
    const filteredPayload = cloneJson(extracted.data);
    const disabledByServer = new Map();
    filteredPayload.tools = filteredPayload.tools.filter(item => {
      if (!item || typeof item.name !== 'string') return false;
      const srvId = String((item.source && item.source.server_id) || 'unknown');
      const leafPath = joinPath([HOTPLUG_ROOT_SEGMENT, srvId, item.name]);
      if (isPathDisabled(leafPath, disabledSet)) {
        if (!disabledByServer.has(srvId)) disabledByServer.set(srvId, []);
        disabledByServer.get(srvId).push(item.name);
        return false;
      }
      return true;
    });
    if (disabledByServer.size > 0) {
      filteredPayload.disabled_tools = [...disabledByServer.entries()].map(([srvId, names]) => ({ [srvId]: names }));
    }
    filteredPayload.disabled_tools_note = disabledNote;
    return writeFilteredJsonToToolResult(result, extracted, filteredPayload);
  }

  if (discoveredNested.pattern !== 'toolsets') return result;

  const isListerCall = Boolean(effectiveMeta.lister && toolName === effectiveMeta.lister);
  const isGroupInspectCall = Boolean(effectiveMeta.groupInspector && toolName === effectiveMeta.groupInspector.name);
  const isLeafInspectCall = Boolean(effectiveMeta.leafInspector && toolName === effectiveMeta.leafInspector.name);
  const isSearchCall = Boolean(effectiveMeta.searchTool && toolName === effectiveMeta.searchTool.name);

  if (!isListerCall && !isGroupInspectCall && !isLeafInspectCall && !isSearchCall) {
    return result;
  }

  const knownToolsetNames = new Set(
    Array.isArray(discoveredNested.toolsets)
      ? discoveredNested.toolsets.map(t => t && String(t.name || '').trim()).filter(Boolean)
      : []
  );

  // Markdown / plain-text lister response filtering (e.g. Unreal list_toolsets)
  if (!extracted && isListerCall) {
    const content = Array.isArray(result.content) ? result.content : [];
    const textIdx = content.findIndex(b => b && b.type === 'text' && typeof b.text === 'string' && b.text.trim());
    if (textIdx < 0) return result;
    const rawText = content[textIdx].text;
    const lines = rawText.split(/\r?\n/);
    const keptLines = [];
    const disabledNames = [];
    let skippingCurrent = false;
    let matchedAny = false;

    for (const line of lines) {
      const m = line.match(/^\s{0,1}(?:[-*+]|\d+\.)\s+`?([A-Za-z0-9_.:-]+)`?(?:\s*[:\-–—]\s*(.*))?$/);
      const candidateName = m ? m[1].trim() : '';
      const isKnownHeader = Boolean(
        candidateName &&
        (knownToolsetNames.size === 0 ||
          knownToolsetNames.has(candidateName) ||
          disabledSet.has(joinPath([TOOLSET_ROOT_SEGMENT, candidateName])))
      );
      if (isKnownHeader) {
        matchedAny = true;
        if (isToolsetFullyDisabled(candidateName, discoveredNested, disabledSet)) {
          skippingCurrent = true;
          disabledNames.push(candidateName);
        } else {
          skippingCurrent = false;
          keptLines.push(line);
        }
      } else if (!skippingCurrent) {
        keptLines.push(line);
      }
    }

    if (!matchedAny || disabledNames.length === 0) return result;
    const copy = cloneJson(result);
    const footer = formatDisabledToolsetsFooter(disabledNames, canSelfManage);
    copy.content[textIdx] = {
      ...copy.content[textIdx],
      type: 'text',
      text: keptLines.join('\n').trim() + footer
    };
    return copy;
  }

  if (!extracted) return result;

  // Key-agnostic recursive JSON filtering across lister, groupInspector, leafInspector, and searchTool
  const safeArgs = isPlainObject(args) ? args : {};
  const requestedGroups = isGroupInspectCall
    ? normalizeStringOrArray(safeArgs[effectiveMeta.groupInspector.targetParam])
    : [];
  const defaultGroup = requestedGroups.length === 1 ? requestedGroups[0] : '';
  const disabledOut = [];

  function pruneLeafObject(item, itemName, currentGroup) {
    const matches = resolveLeafMatches(itemName, currentGroup, discoveredNested);
    const leafPath = matches.length > 0
      ? joinPath(matches[0].segments)
      : (currentGroup
        ? joinPath([TOOLSET_ROOT_SEGMENT, currentGroup, itemName])
        : joinPath([TOOLSET_ROOT_SEGMENT, itemName]));
    const pruned = pruneSchemaForDisabledActions(item, leafPath, disabledSet);
    if (!pruned) {
      disabledOut.push(itemName);
      return null;
    }
    return pruned;
  }

  function filterNode(node, currentGroup, depth) {
    if (depth > 16 || node === null || node === undefined) return node;

    if (Array.isArray(node)) {
      const kept = [];
      for (const item of node) {
        if (typeof item === 'string') {
          const clean = item.trim();
          if (knownToolsetNames.has(clean) && isToolsetFullyDisabled(clean, discoveredNested, disabledSet)) {
            disabledOut.push(clean);
            continue;
          }
          if (isLeafToolDisabled(clean, currentGroup, discoveredNested, disabledSet)) {
            disabledOut.push(clean);
            continue;
          }
          kept.push(item);
        } else if (isPlainObject(item)) {
          const itemName = String(item.name || item.tool_name || item.toolset_name || item.id || '').trim();
          if (itemName && knownToolsetNames.has(itemName) && isToolsetFullyDisabled(itemName, discoveredNested, disabledSet)) {
            disabledOut.push(itemName);
            continue;
          }
          if (itemName && (hasStrongLeafMarkers(item) || currentGroup)) {
            if (isLeafToolDisabled(itemName, currentGroup, discoveredNested, disabledSet)) {
              disabledOut.push(itemName);
              continue;
            }
            const pruned = pruneLeafObject(item, itemName, currentGroup);
            if (!pruned) continue;
            const nextGroup = (itemName && knownToolsetNames.has(itemName)) ? itemName : currentGroup;
            kept.push(filterNode(pruned, nextGroup, depth + 1));
            continue;
          }
          const nextGroup = (itemName && knownToolsetNames.has(itemName)) ? itemName : currentGroup;
          kept.push(filterNode(item, nextGroup, depth + 1));
        } else {
          kept.push(item);
        }
      }
      return kept;
    }

    if (isPlainObject(node)) {
      const ownName = String(node.name || node.toolset_name || node.id || '').trim();
      const nextGroup = (ownName && knownToolsetNames.has(ownName)) ? ownName : currentGroup;
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (SKIP_TRAVERSE_KEYS.has(k)) {
          out[k] = v;
          continue;
        }
        if (knownToolsetNames.has(k) && isToolsetFullyDisabled(k, discoveredNested, disabledSet)) {
          disabledOut.push(k);
          continue;
        }
        if (isPlainObject(v) && hasStrongLeafMarkers(v)) {
          const leafName = String(v.name || v.tool_name || v.id || k).trim();
          if (leafName && isLeafToolDisabled(leafName, nextGroup, discoveredNested, disabledSet)) {
            disabledOut.push(leafName);
            continue;
          }
          const pruned = pruneLeafObject(v, leafName, nextGroup);
          if (!pruned) continue;
          out[k] = filterNode(pruned, knownToolsetNames.has(k) ? k : nextGroup, depth + 1);
          continue;
        }
        const childGroup = knownToolsetNames.has(k) ? k : nextGroup;
        out[k] = filterNode(v, childGroup, depth + 1);
      }
      return out;
    }

    return node;
  }

  const filtered = filterNode(cloneJson(extracted.data), defaultGroup, 0);
  if (disabledOut.length === 0) return result;

  const uniqueDisabled = [...new Set(disabledOut)];
  const finalPayload = isPlainObject(filtered)
    ? { ...filtered, disabled_tools: uniqueDisabled, disabled_tools_note: disabledNote }
    : { items: filtered, disabled_tools: uniqueDisabled, disabled_tools_note: disabledNote };

  return writeFilteredJsonToToolResult(result, extracted, finalPayload);
}

// ----------------------------------------------------------------------------
// Universal empirical nested discovery (covers all 4 MCP archetypes)
// ----------------------------------------------------------------------------
function isTransientDiscoveryError(text) {
  return /timed out|etimedout|econnrefused|econnreset|ehostunreach|enetunreach|socket hang up|socket.*closed|broken pipe|upstream.*unavailable|temporarily unavailable|http\s+50[0234]\b|stalled|superseded|configuration changed|not initialized|session(?:\s+not\s+found|\s+expired|\s+invalid|\s+id)|aborterror|operation was aborted/i.test(String(text || ''));
}

async function callInspectorBatch(callToolFn, inspector, names, allowMarkdownFallback = false) {
  const args = { [inspector.targetParam]: inspector.isArray ? names : names[0] };
  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await callToolFn(inspector.name, args);
      const rawText = getRawTextFromResult(res);
      if (res && res.isError === true) {
        if (isTransientDiscoveryError(rawText)) {
          lastError = new Error(rawText || ('Transient error from ' + inspector.name));
          if (attempt < 2) {
            await new Promise(r => setTimeout(r, 250 * (attempt + 1)));
            continue;
          }
          return { transientError: lastError };
        }
        return { rejected: true, rawText };
      }
      const extracted = extractJsonFromToolResult(res);
      let leaves = extractLeavesBottomUp(extracted ? extracted.data : null);
      if (leaves.length === 0 && extracted && !inspector.isArray) {
        leaves = extractNameOnlyLeavesFallback(extracted.data, names[0]);
      }
      if (leaves.length === 0 && !extracted && allowMarkdownFallback && rawText) {
        leaves = extractLeavesFromMarkdown(rawText, !inspector.isArray ? names[0] : '');
      }
      return { ok: true, leaves, data: extracted ? extracted.data : null, rawText };
    } catch (err) {
      const msg = String(err instanceof Error ? err.message : err);
      if (/JSON-RPC\s+-3260[12]\b/i.test(msg)) return { rejected: true, rawText: msg };
      lastError = err;
      if (attempt < 2) {
        await new Promise(r => setTimeout(r, 250 * (attempt + 1)));
        continue;
      }
      return { transientError: lastError };
    }
  }
  return { transientError: lastError };
}

async function discoverNestedForServer(callToolFn, tools, depth = 0, maxDepth = 5) {
  if (depth >= maxDepth) return null;
  const pattern = detectMetaPattern(tools);
  if (!pattern) return null;

  let transientListerError = null;

  // Phase 1: Try each 0-required-param lister candidate until one yields leaves or expandable groups
  let sawAnyEmptyCandidateList = false;
  for (const listerCand of pattern.listerCandidates) {
    let listRes;
    try {
      listRes = await callToolFn(listerCand.name, {});
    } catch (err) {
      const msg = String(err instanceof Error ? err.message : err);
      if (isTransientDiscoveryError(msg)) transientListerError = err;
      continue;
    }
    if (!listRes || listRes.isError === true) {
      const rawErr = getRawTextFromResult(listRes);
      if (isTransientDiscoveryError(rawErr)) {
        transientListerError = new Error(rawErr || (listerCand.name + ' transient error'));
      }
      continue;
    }

    const extractedList = extractJsonFromToolResult(listRes);
    const rawListText = getRawTextFromResult(listRes);

    // Direct leaf catalog (e.g. nested Hotplug all_tools)
    const directLeaves = extractLeavesBottomUp(extractedList ? extractedList.data : null);
    if (directLeaves.length > 0) {
      const byServer = new Map();
      if (isPlainObject(extractedList && extractedList.data) && Array.isArray(extractedList.data.servers)) {
        for (const srv of extractedList.data.servers) {
          const id = String(srv.id || srv.serverId || '').trim();
          if (id) byServer.set(id, { id, name: String(srv.name || id), tools: [], nested: null });
        }
      }
      for (const leaf of directLeaves) {
        const srvAnc = leaf.ancestors.find(a => !a.isWrapperHint);
        const srvId = srvAnc ? String(srvAnc.id || srvAnc.name) : 'default';
        const srvName = srvAnc ? String(srvAnc.name || srvId) : srvId;
        if (!byServer.has(srvId)) {
          byServer.set(srvId, { id: srvId, name: srvName, tools: [], nested: null });
        }
        const candidateTool = {
          name: leaf.name,
          description: leaf.description,
          inputSchema: isPlainObject(leaf.inputSchema) ? leaf.inputSchema : {}
        };
        if (isExecutableTool(candidateTool)) {
          byServer.get(srvId).tools.push(candidateTool);
        }
      }

      const servers = [...byServer.values()];
      const catalogRevision = String((extractedList && extractedList.data && extractedList.data.catalog_revision) || '');
      for (const srv of servers) {
        const subPattern = detectMetaPattern(srv.tools);
        if (subPattern && depth + 1 < maxDepth) {
          const disp = pattern.dispatcher;
          srv.nested = await discoverNestedForServer(
            (subToolName, subArgs) => {
              const callArgs = { [disp.argsParam]: subArgs || {} };
              callArgs[disp.toolParam] = encodeURIComponent(srv.id) + '::' + encodeURIComponent(subToolName);
              for (const sp of disp.stringParams) {
                if (sp.name !== disp.toolParam && sp.required) callArgs[sp.name] = catalogRevision;
              }
              return callToolFn(disp.name, callArgs);
            },
            srv.tools,
            depth + 1,
            maxDepth
          );
        }
      }

      return {
        pattern: 'hotplug',
        schemaVersion: DISCOVERY_SCHEMA_VERSION,
        discoveredAt: new Date().toISOString(),
        meta: {
          lister: listerCand.name,
          dispatcher: pattern.dispatcher,
          metaTools: [listerCand.name, pattern.dispatcher.name]
        },
        servers
      };
    }

    // Two-step hierarchical toolsets (e.g. Unreal 5.8 / 5.9 / custom grouped MCPs)
    const candidates = extractGroupCandidates(extractedList ? extractedList.data : null, rawListText);
    if (candidates.length === 0) {
      if (pattern.inspectors.length > 0) sawAnyEmptyCandidateList = true;
      continue;
    }
    if (pattern.inspectors.length === 0) continue;

    const candidateSet = new Set(candidates.map(c => c.name));
    const descByGroup = new Map(candidates.map(c => [c.name, c.description]));
    const probeSlice = candidates.slice(0, Math.min(3, candidates.length)).map(c => c.name);

    let groupInspector = null;
    let initialLeaves = [];
    const probedNames = new Set();

    for (const insp of pattern.inspectors) {
      const namesToProbe = insp.isArray ? probeSlice : [probeSlice[0]];
      const probeRes = await callInspectorBatch(callToolFn, insp, namesToProbe, true);
      if (probeRes.transientError) {
        throw probeRes.transientError;
      }
      if (probeRes.ok && probeRes.leaves.length > 0) {
        groupInspector = insp;
        initialLeaves = probeRes.leaves.map(l => {
          if (!l.ancestors.some(a => candidateSet.has(a.name)) && !insp.isArray) {
            l.ancestors.unshift({
              kind: 'group',
              name: namesToProbe[0],
              description: descByGroup.get(namesToProbe[0]) || '',
              fromKey: false,
              isWrapperHint: false
            });
          }
          return l;
        });
        for (const n of namesToProbe) probedNames.add(n);
        break;
      }
    }

    // No inspector expanded this lister's output (e.g. distractor health_check) -> try next lister
    if (!groupInspector) continue;

    // Empirically identify optional leaf-level inspector (e.g. describe_tools)
    let leafInspector = null;
    const sampleLeafName = initialLeaves[0] && initialLeaves[0].name;
    if (sampleLeafName) {
      for (const insp of pattern.inspectors) {
        if (insp.name === groupInspector.name) continue;
        const probeRes = await callInspectorBatch(callToolFn, insp, [sampleLeafName], false);
        if (probeRes.ok && probeRes.leaves.length > 0) {
          leafInspector = insp;
          break;
        }
      }
    }

    const remaining = candidates.map(c => c.name).filter(n => !probedNames.has(n));
    const allLeaves = [...initialLeaves];
    const failedToolsets = [];

    async function processGroupChunk(chunk) {
      const res = await callInspectorBatch(callToolFn, groupInspector, chunk, true);
      if (res.transientError) {
        failedToolsets.push(...chunk);
        return;
      }
      if (res.rejected) {
        if (groupInspector.isArray && chunk.length > 1) {
          const mid = Math.ceil(chunk.length / 2);
          await processGroupChunk(chunk.slice(0, mid));
          await processGroupChunk(chunk.slice(mid));
        }
        return;
      }
      if (res.ok && res.leaves.length > 0) {
        for (const l of res.leaves) {
          if (!l.ancestors.some(a => candidateSet.has(a.name)) && chunk.length === 1) {
            l.ancestors.unshift({
              kind: 'group',
              name: chunk[0],
              description: descByGroup.get(chunk[0]) || '',
              fromKey: false,
              isWrapperHint: false
            });
          }
          allLeaves.push(l);
        }
      }
    }

    const chunkSize = groupInspector.isArray ? 16 : 1;
    const chunks = [];
    for (let i = 0; i < remaining.length; i += chunkSize) {
      chunks.push(remaining.slice(i, i + chunkSize));
    }
    const concurrency = 4;
    for (let i = 0; i < chunks.length; i += concurrency) {
      await Promise.all(chunks.slice(i, i + concurrency).map(processGroupChunk));
    }

    if (failedToolsets.length > 0) {
      throw new Error('Incomplete nested toolset discovery; failed toolsets: ' + failedToolsets.join(', '));
    }

    const detailed = groupLeavesIntoToolsets(allLeaves, candidateSet, descByGroup);
    const verifiedMetaTools = [listerCand.name, groupInspector.name, pattern.dispatcher.name];
    if (leafInspector) verifiedMetaTools.push(leafInspector.name);

    return {
      pattern: 'toolsets',
      schemaVersion: DISCOVERY_SCHEMA_VERSION,
      discoveredAt: new Date().toISOString(),
      meta: {
        lister: listerCand.name,
        dispatcher: pattern.dispatcher,
        groupInspector,
        leafInspector,
        metaTools: verifiedMetaTools
      },
      toolsets: detailed
    };
  }

  if (transientListerError) {
    throw transientListerError;
  }

  // If a hierarchical lister succeeded without throwing, but returned 0 candidates while subsystems are still warming up,
  // retry instead of caching pattern='none' permanently.
  if (sawAnyEmptyCandidateList) {
    throw new Error('Hierarchical lister returned an empty candidate list; retrying discovery.');
  }

  // Phase 2: Search-based proxy (no 0-arg lister, e.g. FastMCP search_tools + call_tool)
  for (const insp of pattern.inspectors) {
    if (insp.isArray) continue;
    for (const broadQuery of ['.*', '', '*']) {
      const args = { [insp.targetParam]: broadQuery };
      const limitOpt = insp.optionalParams.find(p => p.types.includes('integer') || p.types.includes('number'));
      if (limitOpt) args[limitOpt.name] = 500;

      let res;
      try {
        res = await callToolFn(insp.name, args);
      } catch (err) {
        const msg = String(err instanceof Error ? err.message : err);
        if (isTransientDiscoveryError(msg)) throw err;
        continue;
      }
      if (!res || res.isError === true) {
        const rawErr = getRawTextFromResult(res);
        if (isTransientDiscoveryError(rawErr)) throw new Error(rawErr);
        continue;
      }

      const extracted = extractJsonFromToolResult(res);
      const rawText = getRawTextFromResult(res);
      let leaves = extractLeavesBottomUp(extracted ? extracted.data : null);
      if (leaves.length === 0 && !extracted && rawText) {
        leaves = extractLeavesFromMarkdown(rawText, '');
      }
      if (leaves.length > 0) {
        const detailed = groupLeavesIntoToolsets(leaves, new Set(), new Map());
        return {
          pattern: 'toolsets',
          schemaVersion: DISCOVERY_SCHEMA_VERSION,
          discoveredAt: new Date().toISOString(),
          meta: {
            lister: null,
            searchTool: insp,
            dispatcher: pattern.dispatcher,
            groupInspector: null,
            leafInspector: null,
            metaTools: [insp.name, pattern.dispatcher.name]
          },
          toolsets: detailed
        };
      }
    }
  }

  // Confirmed not a meta-MCP server: settle cleanly as flat without infinite retries.
  return {
    pattern: 'none',
    schemaVersion: DISCOVERY_SCHEMA_VERSION,
    discoveredAt: new Date().toISOString(),
    toolsets: []
  };
}

function indexServerToolTree(tree) {
  const leafEnabledMap = new Map();
  const leafByCanonical = new Map();
  const categoryByFullName = new Map();
  const topCategories = [];
  const flatLeaves = [];

  function formatLeafCanonicalName(node, ctx) {
    if (node.metaType === 'schema_action' && ctx.schemaRootCanonical) {
      return ctx.schemaRootCanonical + '/' + node.name;
    }
    if (ctx.toolsetName) {
      if (node.name === ctx.toolsetName || node.name.startsWith(ctx.toolsetName + '.')) {
        return node.name;
      }
      return ctx.toolsetName + '/' + node.name;
    }
    if (ctx.hotplugServerName) {
      return ctx.hotplugServerName + '/' + node.name;
    }
    return node.name;
  }

  function registerLeaf(node, ctx, targetLeafList) {
    const canonicalName = formatLeafCanonicalName(node, ctx);
    const leafRecord = {
      path: node.path,
      name: node.name,
      canonicalName,
      enabled: Boolean(node.enabled),
      categoryName: ctx.topCategoryName || null
    };
    leafEnabledMap.set(node.path, leafRecord.enabled);
    if (!leafByCanonical.has(canonicalName)) {
      leafByCanonical.set(canonicalName, leafRecord);
    }
    if (Array.isArray(targetLeafList)) {
      targetLeafList.push(leafRecord);
    }
    return leafRecord;
  }

  function collectSubtreeLeaves(node, ctx, outLeaves) {
    if (node.kind === 'tool') {
      registerLeaf(node, ctx, outLeaves);
      return;
    }

    const nextCtx = { ...ctx };
    if (node.metaType === 'schema_root') {
      nextCtx.schemaRootCanonical = formatLeafCanonicalName(node, ctx);
    }

    const children = Array.isArray(node.children) ? node.children : [];
    if (node.metaType === 'subcategory') {
      const subFullName = ctx.categoryPrefix ? (ctx.categoryPrefix + '/' + node.name) : node.name;
      nextCtx.categoryPrefix = subFullName;
      const subLeaves = [];
      for (const child of children) {
        collectSubtreeLeaves(child, nextCtx, subLeaves);
      }
      for (const leaf of subLeaves) outLeaves.push(leaf);
      if (!categoryByFullName.has(subFullName)) {
        categoryByFullName.set(subFullName, {
          name: subFullName,
          node,
          leaves: subLeaves,
          isTopLevel: false
        });
      }
      return;
    }

    for (const child of children) {
      collectSubtreeLeaves(child, nextCtx, outLeaves);
    }
  }

  function processTopNode(node, isFromToolsetRoot = false, isFromHotplugRoot = false) {
    if (node.metaType === 'toolset_root') {
      for (const child of node.children || []) {
        processTopNode(child, true, false);
      }
      return;
    }
    if (node.metaType === 'hotplug_root') {
      for (const child of node.children || []) {
        processTopNode(child, false, true);
      }
      return;
    }

    if (node.kind === 'category') {
      const catName = node.name;
      const leaves = [];
      const ctx = {
        topCategoryName: catName,
        categoryPrefix: catName,
        toolsetName: node.metaType === 'toolset' ? catName : null,
        hotplugServerName: node.metaType === 'hotplug_server' ? catName : null,
        schemaRootCanonical: node.metaType === 'schema_root' ? catName : null
      };
      for (const child of node.children || []) {
        collectSubtreeLeaves(child, ctx, leaves);
      }
      const catRecord = { name: catName, node, leaves, isTopLevel: true };
      categoryByFullName.set(catName, catRecord);
      topCategories.push(catRecord);
      return;
    }

    if (isFromToolsetRoot) {
      // Single-tool toolset (isSingleTool === true): expose both as category and leaf tool.
      const catName = node.name;
      const leaves = [];
      registerLeaf(node, { topCategoryName: catName, toolsetName: catName }, leaves);
      const catRecord = { name: catName, node, leaves, isTopLevel: true };
      categoryByFullName.set(catName, catRecord);
      topCategories.push(catRecord);
      return;
    }

    const leafCtx = {
      topCategoryName: null,
      hotplugServerName: isFromHotplugRoot ? node.name : null
    };
    registerLeaf(node, leafCtx, flatLeaves);
  }

  for (const root of (tree && tree.nodes) || []) {
    processTopNode(root, false, false);
  }

  return {
    leafEnabledMap,
    leafByCanonical,
    categoryByFullName,
    topCategories,
    flatLeaves
  };
}

function collapseDisabledPaths(tree, leafEnabledMap) {
  const result = [];

  function visit(node) {
    if (node.kind === 'tool') {
      const isEnabled = leafEnabledMap.has(node.path) ? Boolean(leafEnabledMap.get(node.path)) : Boolean(node.enabled);
      if (!isEnabled) result.push(node.path);
      return isEnabled ? 'all' : 'none';
    }

    const children = Array.isArray(node.children) ? node.children : [];
    if (children.length === 0) {
      const isEnabled = leafEnabledMap.has(node.path) ? Boolean(leafEnabledMap.get(node.path)) : Boolean(node.enabled);
      if (!isEnabled) result.push(node.path);
      return isEnabled ? 'all' : 'none';
    }

    const startIdx = result.length;
    let allEnabled = true;
    let allDisabled = true;
    for (const child of children) {
      const childState = visit(child);
      if (childState !== 'all') allEnabled = false;
      if (childState !== 'none') allDisabled = false;
    }

    if (allDisabled) {
      result.length = startIdx;
      result.push(node.path);
      return 'none';
    }
    return allEnabled ? 'all' : 'partial';
  }

  for (const root of (tree && tree.nodes) || []) {
    visit(root);
  }

  return normalizeDisabledList(result);
}

function summarizeCategoryRecord(catRecord) {
  let enabled = 0;
  const total = catRecord.leaves.length;
  for (const leaf of catRecord.leaves) {
    if (leaf.enabled) enabled += 1;
  }
  const status = total === 0
    ? (catRecord.node.enabled ? 'enabled' : 'disabled')
    : (enabled === total ? 'enabled' : (enabled === 0 ? 'disabled' : 'partial'));
  return { name: catRecord.name, status, enabled, total };
}

function inspectServerToolTree(tree, options = {}) {
  const index = indexServerToolTree(tree);
  const statusFilter = options.status === 'enabled' || options.status === 'disabled' ? options.status : 'all';
  const searchRaw = typeof options.search === 'string' ? options.search.trim().toLowerCase() : '';
  const requestedCategories = Array.isArray(options.categories)
    ? [...new Set(options.categories.filter(c => typeof c === 'string' && c.trim()).map(c => c.trim()))]
    : [];

  const leafMatchesStatus = (leaf) =>
    statusFilter === 'all' || (statusFilter === 'enabled' ? leaf.enabled : !leaf.enabled);
  const categoryMatchesStatus = (summary) =>
    statusFilter === 'all' ||
    (statusFilter === 'enabled' ? summary.enabled > 0 : summary.enabled < summary.total);

  if (requestedCategories.length > 0) {
    const categoriesResult = {};
    const notFound = [];
    for (const catName of requestedCategories) {
      const cat = index.categoryByFullName.get(catName);
      if (!cat) {
        notFound.push(catName);
        continue;
      }
      const enabledList = [];
      const disabledList = [];
      for (const leaf of cat.leaves) {
        if (!leafMatchesStatus(leaf)) continue;
        if (searchRaw && !leaf.canonicalName.toLowerCase().includes(searchRaw)) continue;
        if (leaf.enabled) enabledList.push(leaf.canonicalName);
        else disabledList.push(leaf.canonicalName);
      }
      categoriesResult[catName] = {
        ...(statusFilter !== 'disabled' ? { enabled: enabledList } : {}),
        ...(statusFilter !== 'enabled' ? { disabled: disabledList } : {})
      };
    }
    return {
      has_categories: true,
      categories: categoriesResult,
      ...(notFound.length > 0 ? { not_found: notFound } : {})
    };
  }

  if (searchRaw) {
    const matchedCategories = [];
    for (const cat of index.topCategories) {
      if (!cat.name.toLowerCase().includes(searchRaw)) continue;
      const summary = summarizeCategoryRecord(cat);
      if (categoryMatchesStatus(summary)) matchedCategories.push(summary);
    }
    const enabledTools = [];
    const disabledTools = [];
    for (const leaf of index.leafByCanonical.values()) {
      if (!leafMatchesStatus(leaf)) continue;
      if (!leaf.canonicalName.toLowerCase().includes(searchRaw)) continue;
      if (leaf.enabled) enabledTools.push(leaf.canonicalName);
      else disabledTools.push(leaf.canonicalName);
    }
    return {
      has_categories: index.topCategories.length > 0,
      ...(matchedCategories.length > 0 ? { matched_categories: matchedCategories } : {}),
      ...(statusFilter !== 'disabled' ? { enabled_tools: enabledTools } : {}),
      ...(statusFilter !== 'enabled' ? { disabled_tools: disabledTools } : {})
    };
  }

  if (index.topCategories.length > 0) {
    const categories = index.topCategories
      .map(summarizeCategoryRecord)
      .filter(categoryMatchesStatus);
    const result = {
      has_categories: true,
      categories
    };
    if (index.flatLeaves.length > 0) {
      const enabledFlat = index.flatLeaves.filter(l => l.enabled && leafMatchesStatus(l)).map(l => l.canonicalName);
      const disabledFlat = index.flatLeaves.filter(l => !l.enabled && leafMatchesStatus(l)).map(l => l.canonicalName);
      if (enabledFlat.length > 0 || disabledFlat.length > 0) {
        result.flat_tools = {
          ...(statusFilter !== 'disabled' ? { enabled: enabledFlat } : {}),
          ...(statusFilter !== 'enabled' ? { disabled: disabledFlat } : {})
        };
      }
    }
    return result;
  }

  const enabledTools = index.flatLeaves.filter(l => l.enabled && leafMatchesStatus(l)).map(l => l.canonicalName);
  const disabledTools = index.flatLeaves.filter(l => !l.enabled && leafMatchesStatus(l)).map(l => l.canonicalName);
  return {
    has_categories: false,
    ...(statusFilter !== 'disabled' ? { enabled_tools: enabledTools } : {}),
    ...(statusFilter !== 'enabled' ? { disabled_tools: disabledTools } : {})
  };
}

function applyServerToolMutations(tree, mutation) {
  const index = indexServerToolTree(tree);
  const initialMap = new Map(index.leafEnabledMap);
  const nextMap = new Map(index.leafEnabledMap);
  const notFound = [];

  const setCategoryLeaves = (cat, enabled) => {
    for (const leaf of cat.leaves) {
      nextMap.set(leaf.path, enabled);
    }
  };

  if (mutation.reset_all === 'enable') {
    for (const leafPath of nextMap.keys()) nextMap.set(leafPath, true);
  } else if (mutation.reset_all === 'disable') {
    for (const leafPath of nextMap.keys()) nextMap.set(leafPath, false);
  }

  if (Array.isArray(mutation.keep_only_categories)) {
    const matched = [];
    for (const rawName of mutation.keep_only_categories) {
      if (typeof rawName !== 'string' || !rawName.trim()) continue;
      const name = rawName.trim();
      const cat = index.categoryByFullName.get(name);
      if (cat) matched.push(cat);
      else notFound.push(name);
    }
    if (matched.length > 0 || mutation.keep_only_categories.length === 0) {
      for (const leafPath of nextMap.keys()) nextMap.set(leafPath, false);
      for (const cat of matched) setCategoryLeaves(cat, true);
    }
  }

  if (Array.isArray(mutation.disable_categories)) {
    for (const rawName of mutation.disable_categories) {
      if (typeof rawName !== 'string' || !rawName.trim()) continue;
      const name = rawName.trim();
      const cat = index.categoryByFullName.get(name);
      if (cat) setCategoryLeaves(cat, false);
      else notFound.push(name);
    }
  }

  if (Array.isArray(mutation.enable_categories)) {
    for (const rawName of mutation.enable_categories) {
      if (typeof rawName !== 'string' || !rawName.trim()) continue;
      const name = rawName.trim();
      const cat = index.categoryByFullName.get(name);
      if (cat) setCategoryLeaves(cat, true);
      else notFound.push(name);
    }
  }

  if (Array.isArray(mutation.keep_only_tools)) {
    const matched = [];
    for (const rawName of mutation.keep_only_tools) {
      if (typeof rawName !== 'string' || !rawName.trim()) continue;
      const name = rawName.trim();
      const leaf = index.leafByCanonical.get(name);
      if (leaf) matched.push(leaf);
      else notFound.push(name);
    }
    if (matched.length > 0 || mutation.keep_only_tools.length === 0) {
      for (const leafPath of nextMap.keys()) nextMap.set(leafPath, false);
      for (const leaf of matched) nextMap.set(leaf.path, true);
    }
  } else if (isPlainObject(mutation.keep_only_tools)) {
    for (const [rawCatName, rawToolNames] of Object.entries(mutation.keep_only_tools)) {
      const catName = String(rawCatName || '').trim();
      const cat = index.categoryByFullName.get(catName);
      if (!cat) {
        notFound.push(catName);
        continue;
      }
      const list = Array.isArray(rawToolNames) ? rawToolNames : [];
      const catLeafByCanonical = new Map(cat.leaves.map(l => [l.canonicalName, l]));
      const catLeafByName = new Map(cat.leaves.map(l => [l.name, l]));
      const matched = [];
      for (const rawTool of list) {
        if (typeof rawTool !== 'string' || !rawTool.trim()) continue;
        const toolName = rawTool.trim();
        const leaf = catLeafByCanonical.get(toolName) || catLeafByName.get(toolName);
        if (leaf) matched.push(leaf);
        else notFound.push(toolName);
      }
      if (matched.length > 0 || list.length === 0) {
        setCategoryLeaves(cat, false);
        for (const leaf of matched) nextMap.set(leaf.path, true);
      }
    }
  }

  if (Array.isArray(mutation.disable_tools)) {
    for (const rawName of mutation.disable_tools) {
      if (typeof rawName !== 'string' || !rawName.trim()) continue;
      const name = rawName.trim();
      const leaf = index.leafByCanonical.get(name);
      if (leaf) nextMap.set(leaf.path, false);
      else notFound.push(name);
    }
  }

  if (Array.isArray(mutation.enable_tools)) {
    for (const rawName of mutation.enable_tools) {
      if (typeof rawName !== 'string' || !rawName.trim()) continue;
      const name = rawName.trim();
      const leaf = index.leafByCanonical.get(name);
      if (leaf) nextMap.set(leaf.path, true);
      else notFound.push(name);
    }
  }

  let changedCount = 0;
  let enabledCount = 0;
  const totalCount = nextMap.size;
  for (const [leafPath, isEnabled] of nextMap.entries()) {
    if (isEnabled) enabledCount += 1;
    if (initialMap.get(leafPath) !== isEnabled) changedCount += 1;
  }

  const disabledTools = collapseDisabledPaths(tree, nextMap);
  return {
    disabledTools,
    changedCount,
    enabledCount,
    totalCount,
    notFound: [...new Set(notFound)]
  };
}

module.exports = {
  DISCOVERY_SCHEMA_VERSION,
  HOTPLUG_CONTROL_SERVER_ID,
  HOTPLUG_CONTROL_MANAGE_TOOL,
  HOTPLUG_CONTROL_LIST_TOOL,
  DISABLED_TOOLS_NOTE,
  DISABLED_TOOLS_NOTE_USER_ONLY,
  DISABLED_TOOLS_NOTE_SELF_MANAGE,
  GATEWAY_ALL_TOOLS_DESCRIPTION,
  TOOLSET_ROOT_SEGMENT,
  HOTPLUG_ROOT_SEGMENT,
  getDisabledToolsNote,
  formatToolDisabledMessage,
  formatDisabledToolsetsFooter,
  encodeSegment,
  decodeSegment,
  joinPath,
  splitPath,
  normalizeDisabledList,
  createDisabledSet,
  isPathDisabled,
  detectMetaPattern,
  extractSchemaSubActions,
  buildServerToolTree,
  buildCompactDisabledHierarchy,
  collapseDisabledPaths,
  inspectServerToolTree,
  applyServerToolMutations,
  filterCatalogToolsForServer,
  checkToolCallAllowed,
  filterToolCallResponse,
  discoverNestedForServer
};

// 浏览器端持久化（IndexedDB kv；项目相关状态跨刷新保留）。
//
// 存什么：工作区根、上次打开的文件、未保存草稿（编辑器文本 vs 磁盘的差异）、
// 面板选择。不存什么：生成的产物（层栈/HEX/诊断——打开即重算，属「生成的文件」）。
// IndexedDB 不可用（隐私模式等）时退化为内存 Map：功能不中断，仅不跨刷新。
//
// 草稿语义：draft:<root>:<path> 只在「编辑器文本 ≠ 磁盘文本」时存在——保存成功
// 或文件删除即清除；重新打开文件时若有草稿则恢复草稿并标记未保存（savedText =
// 磁盘文本）。

const DB_NAME = "prping-web";
const STORE = "kv";

export type KvValue = unknown;

/** 打开（或退化创建）kv 存储；统一句柄。 */
function open(): Promise<{
  get(key: string): Promise<KvValue | null>;
  set(key: string, v: KvValue): Promise<void>;
  del(key: string): Promise<void>;
  keys(prefix?: string): Promise<string[]>;
}> {
  const memory = new Map<string, KvValue>();
  if (typeof indexedDB === "undefined") {
    // 隐私模式 / 旧浏览器：内存兜底
    return Promise.resolve({
      get: async (k) => memory.get(k) ?? null,
      set: async (k, v) => void memory.set(k, v),
      del: async (k) => void memory.delete(k),
      keys: async (prefix?: string) =>
        [...memory.keys()].filter((k) => (prefix ? k.startsWith(prefix) : true)),
    });
  }
  return new Promise((resolve) => {
    let db: IDBDatabase | null = null;
    try {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => {
        db = req.result;
        resolve(idbImpl(() => db!));
      };
      req.onerror = () => resolve(memImpl(memory));
    } catch {
      resolve(memImpl(memory));
    }
  });
}

function idbImpl(db: () => IDBDatabase) {
  return {
    keys(prefix?: string): Promise<string[]> {
      return new Promise((resolve) => {
        try {
          // 前缀 → [prefix, prefix+\uffff) 闭开区间（\uffff 大于一切合法键字符）
          const range = prefix ? IDBKeyRange.bound(prefix, prefix + "\uffff", false, true) : null;
          const r = db().transaction(STORE, "readonly").objectStore(STORE).openCursor(range);
          const out: string[] = [];
          r.onsuccess = () => {
            const c = r.result;
            if (c) {
              out.push(String(c.key));
              c.continue();
            } else {
              resolve(out);
            }
          };
          r.onerror = () => resolve(out);
        } catch {
          resolve([]);
        }
      });
    },
    get(key: string): Promise<KvValue | null> {
      return new Promise((resolve) => {
        try {
          const r = db().transaction(STORE, "readonly").objectStore(STORE).get(key);
          r.onsuccess = () => resolve((r.result as KvValue) ?? null);
          r.onerror = () => resolve(null);
        } catch {
          resolve(null);
        }
      });
    },
    set(key: string, v: KvValue): Promise<void> {
      return new Promise((resolve) => {
        try {
          const r = db().transaction(STORE, "readwrite").objectStore(STORE).put(v, key);
          r.onsuccess = () => resolve();
          r.onerror = () => resolve();
        } catch {
          resolve();
        }
      });
    },
    del(key: string): Promise<void> {
      return new Promise((resolve) => {
        try {
          const r = db().transaction(STORE, "readwrite").objectStore(STORE).delete(key);
          r.onsuccess = () => resolve();
          r.onerror = () => resolve();
        } catch {
          resolve();
        }
      });
    },
  };
}

function memImpl(memory: Map<string, KvValue>) {
  return {
    get: async (k: string) => memory.get(k) ?? null,
    set: async (k: string, v: KvValue) => void memory.set(k, v),
    del: async (k: string) => void memory.delete(k),
    keys: async (prefix?: string) =>
      [...memory.keys()].filter((k) => (prefix ? k.startsWith(prefix) : true)),
  };
}

const store = open();

/** 读 kv（未命中/出错 → null）。 */
export async function kvGet<T>(key: string): Promise<T | null> {
  return (await store).get(key) as Promise<T | null>;
}

/** 写 kv（出错静默——持久化失败不阻塞编辑）。 */
export async function kvSet(key: string, value: KvValue): Promise<void> {
  await (await store).set(key, value);
}

/** 删 kv。 */
export async function kvDel(key: string): Promise<void> {
  await (await store).del(key);
}

/** 列出前缀匹配的键（草稿 GC 用；IndexedDB 不可用退内存 Map，同样支持）。 */
export async function kvKeys(prefix: string): Promise<string[]> {
  return (await store).keys(prefix);
}

/** 草稿键（工作区/库文件统一编址）。 */
export function draftKey(root: "ws" | "lib", path: string): string {
  return `draft:${root}:${path}`;
}

// 常用键名（避免散落魔法串）
export const Keys = {
  workspaceRoot: "workspaceRoot", // 自定义工作区根（重载后恢复）
  lastFile: "lastFile", // { root, path } 上次打开的文件
  panel: "panel", // 右侧面板选择
  runSettings: "runSettings", // Run 面板选项快照（target/count/wait/...）
} as const;

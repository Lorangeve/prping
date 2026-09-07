from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

PK = "crates/prping-core/src/engine/pkg/recipe.rs"
sub(PK, """                        Ok(Some(super::listen::UdpListen::Hit {
                            data,
                            fields,
                            peer,
                            until_matched,
                        })) => {
                            listen_matched(&mut w, opts, &data, &fields, Some(&peer))?;
                            listen_peer = Some(peer);
                            listen_reply = Some(data);""", """                        Ok(Some(super::listen::UdpListen::Hit {
                            data,
                            fields,
                            peer,
                            until_matched,
                        })) => {
                            listen_matched(&mut w, opts, &data, &fields, Some(&peer))?;
                            listen_peer = Some(peer);
                            listen_reply = Some(data);
                            // hits() 计数：单规则直听命中也计入阶段命中累计
                            if let Some(ctx) = &step.loop_ctx
                                && let Some(run) = loop_runs.get_mut(&ctx.id)
                            {
                                run.hits += 1;
                            }""", "udp-hit-hits")
sub(PK, """                        Ok(Some(super::listen_raw::RawListen::Hit {
                            data,
                            until_matched,
                        })) => {
                            listen_matched(&mut w, opts, &data, &[], None)?;
                            listen_reply = Some(data);""", """                        Ok(Some(super::listen_raw::RawListen::Hit {
                            data,
                            until_matched,
                        })) => {
                            listen_matched(&mut w, opts, &data, &[], None)?;
                            listen_reply = Some(data);
                            // hits() 计数：单规则直听命中也计入阶段命中累计
                            if let Some(ctx) = &step.loop_ctx
                                && let Some(run) = loop_runs.get_mut(&ctx.id)
                            {
                                run.hits += 1;
                            }""", "raw-hit-hits")
print("hits increments OK")
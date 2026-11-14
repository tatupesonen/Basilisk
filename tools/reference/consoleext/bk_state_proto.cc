/* Basilisk console extension: the @proto, @callspecs and @jumptables
 * sections of the state dump (bk_state.hh). */
#include "bk_state.hh"

namespace bk {

/// Letters for a parameter's properties: t type lock, n name lock, z size
/// lock, h this pointer, i indirect storage, r hidden return, u name undefined.
static std::string paramFlags(ProtoParameter *p)
{
  std::string s;
  if (p->isTypeLocked()) s += 't';
  if (p->isNameLocked()) s += 'n';
  if (p->isSizeTypeLocked()) s += 'z';
  if (p->isThisPointer()) s += 'h';
  if (p->isIndirectStorage()) s += 'i';
  if (p->isHiddenReturn()) s += 'r';
  if (p->isNameUndefined()) s += 'u';
  return s.empty() ? std::string("-") : s;
}

static std::string paramRecord(StateDump &d, const char *dir, int4 i, ProtoParameter *p)
{
  return record({"Q", dir, num(i), escape(p->getName()), addrText(p->getAddress()), num(p->getSize()),
                 d.ids.type(p->getType()), paramFlags(p)});
}

/// `M`, `Q`, `X`, `Y` records of a prototype.
static void writeProto(StateDump &d, const FuncProto &proto)
{
  const ProtoModel *model = proto.model;
  // FuncProto's constructor leaves extrapop uninitialised; setModel sets it.
  // A call spec has no model between flow and ActionDefaultParams (queryCall
  // postpones the copy of the callee's prototype), so extrapop is written
  // only with a model.
  bool hasModel = (model != (const ProtoModel *)0);
  d.w.add(record({"M", hasModel ? escape(model->getName()) : std::string("-"),
                  hasModel ? num(proto.extrapop) : std::string("-"), hx(proto.flags), num(proto.injectid),
                  num(proto.returnBytesConsumed)}));
  ProtoStore *store = proto.store;
  if (store != (ProtoStore *)0) {
    for (int4 i = 0; i < store->getNumInputs(); ++i) {
      ProtoParameter *p = store->getInput(i);
      if (p != (ProtoParameter *)0) d.w.add(paramRecord(d, "in", i, p));
    }
    ProtoParameter *out = store->getOutput();
    if (out != (ProtoParameter *)0) d.w.add(paramRecord(d, "out", 0, out));
  }
  if (model != (const ProtoModel *)0) {
    for (vector<EffectRecord>::const_iterator it = proto.effectBegin(); it != proto.effectEnd(); ++it)
      d.w.add(record({"X", num((*it).getType()), addrText((*it).getAddress()), num((*it).getSize())}));
    for (vector<VarnodeData>::const_iterator it = proto.trashBegin(); it != proto.trashEnd(); ++it)
      d.w.add(record({"Y", addrText(Address((*it).space, (*it).offset)), num((*it).size)}));
  }
}

/// A trial's model entry, named by its storage: `<space>:0x<base>:<size>`.
static std::string entryText(const ParamEntry *e)
{
  if (e == (const ParamEntry *)0) return "-";
  return e->spaceid->getName() + ":" + hx(e->addressbase) + ":" + num(e->size);
}

/// `A` and `T` records of a ParamActive.
static void writeActive(StateDump &d, const char *dir, const ParamActive &pa)
{
  d.w.add(record({"A", dir, num(pa.slotbase), num(pa.stackplaceholder), num(pa.numpasses), num(pa.maxpass),
                  flag(pa.isfullychecked), flag(pa.needsfinalcheck), flag(pa.recoversubcall),
                  flag(pa.joinMostSigFirst)}));
  for (size_t i = 0; i < pa.trial.size(); ++i) {
    const ParamTrial &t(pa.trial[i]);
    d.w.add(record({"T", addrText(t.addr), num(t.size), hx(t.flags), entryText(t.entry), num(t.slot), num(t.offset),
                    num(t.fixedPosition)}));
  }
}

void writeProtoSection(StateDump &d)
{
  d.w.begin("proto");
  writeProto(d, d.fd->funcp);
  if (d.fd->activeoutput != (ParamActive *)0) writeActive(d, "out", *d.fd->activeoutput);
  d.w.end();
}

/// matchCallCount is left out: no constructor initialises it and nothing in
/// the decompiler sets it (FuncCallSpecs::countMatchingCalls has no caller).
void writeCallSpecSection(StateDump &d)
{
  d.w.begin("callspecs");
  for (size_t k = 0; k < d.fd->qlst.size(); ++k) {
    FuncCallSpecs *fc = d.fd->qlst[k];
    std::vector<std::string> consume;
    for (size_t i = 0; i < fc->inputConsume.size(); ++i) consume.push_back(num(fc->inputConsume[i]));
    d.w.add(record({"C", d.ids.call(fc), d.ids.op(fc->op), escape(fc->name), addrText(fc->entryaddress),
                    num(fc->effective_extrapop), hx(fc->stackoffset), num(fc->stackPlaceholderSlot),
                    num(fc->paramshift), flag(fc->isinputactive), flag(fc->isoutputactive),
                    flag(fc->isbadjumptable), flag(fc->isstackoutputlock), joinList(consume)}));
    writeProto(d, *fc);
    if (fc->isinputactive) writeActive(d, "in", fc->activeinput);
    if (fc->isoutputactive) writeActive(d, "out", fc->activeoutput);
  }
  d.w.end();
}

/// The kind of a jump-table model.
static std::string modelKind(const JumpModel *m)
{
  if (m == (const JumpModel *)0) return "-";
  if (dynamic_cast<const JumpBasicOverride *>(m) != 0) return "basicoverride";
  if (dynamic_cast<const JumpBasic2 *>(m) != 0) return "basic2";
  if (dynamic_cast<const JumpBasic *>(m) != 0) return "basic";
  if (dynamic_cast<const JumpAssisted *>(m) != 0) return "assisted";
  if (dynamic_cast<const JumpModelTrivial *>(m) != 0) return "trivial";
  return "other";
}

void writeJumpTableSection(StateDump &d)
{
  d.w.begin("jumptables");
  for (size_t k = 0; k < d.fd->jumpvec.size(); ++k) {
    JumpTable *jt = d.fd->jumpvec[k];
    std::vector<std::string> addrs, pairs, labels;
    for (size_t i = 0; i < jt->addresstable.size(); ++i) addrs.push_back(addrText(jt->addresstable[i]));
    for (size_t i = 0; i < jt->block2addr.size(); ++i)
      pairs.push_back(num(jt->block2addr[i].blockPosition) + ":" + num(jt->block2addr[i].addressIndex));
    for (size_t i = 0; i < jt->label.size(); ++i) labels.push_back(hx(jt->label[i]));
    d.w.add(record({"J", "j" + num((intb)k), d.ids.op(jt->indirect), addrText(jt->opaddress), joinList(addrs),
                    joinList(pairs), joinList(labels), num(jt->defaultBlock), num(jt->lastBlock),
                    hx(jt->switchVarConsume), num(jt->recoverCount), hx(jt->displayFormat), flag(jt->partialTable),
                    flag(jt->collectloads), flag(jt->defaultIsFolded), modelKind(jt->jmodel),
                    modelKind(jt->origmodel), flag(jt->isOverride())}));
    for (size_t i = 0; i < jt->loadpoints.size(); ++i) {
      const LoadTable &lt(jt->loadpoints[i]);
      d.w.add(record({"D", addrText(lt.addr), num(lt.size), num(lt.num)}));
    }
  }
  d.w.end();
}

} // namespace bk

#ifndef RCDATA_H
#define RCDATA_H


#include "config.h"
#include "types.h"
#include "Nonce.h"
#include "Hash.h"


#include "salticidae/stream.h"


// Round Data
class RCData {
 private:
  Hash   preph;
  View   prepv = 0;
  View   view = 0;
  Nonce  nonce;

 public:
  RCData(Hash preph, View prepv, View view, Nonce nonce);
  RCData(salticidae::DataStream &data);
  RCData();

  Hash   getPreph();
  View   getPrepv();
  View   getView();
  Nonce  getNonce();

  void serialize(salticidae::DataStream &data) const;
  void unserialize(salticidae::DataStream &data);

  std::string prettyPrint();
  std::string toString();

  bool operator==(const RCData& s) const;
};


#endif

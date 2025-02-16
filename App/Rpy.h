#ifndef RPY_H
#define RPY_H


#include "Signs.h"
#include "RCData.h"

#include "salticidae/stream.h"


class Rpy {

 private:
  bool set = false;
  RCData rcdata; // round data
  Sign sign; // signature

 public:
  Rpy();
  Rpy(RCData rcdata, Sign sign);
  Rpy(bool b, RCData rcdata, Sign sign);

  bool  isSet();
  RCData getRCData();
  Sign getSign();

  void serialize(salticidae::DataStream &data) const;
  void unserialize(salticidae::DataStream &data);

  std::string prettyPrint();
  std::string toString();


  View getRCView();
  Hash getRCHash();
};


#endif
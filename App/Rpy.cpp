#include "Rpy.h"

Rpy::Rpy() {
  this->set   = false;
  this->rcdata = RCData();
  this->sign = Sign();
}

Rpy::Rpy(RCData rcdata, Sign sign) {
  this->set   = true;
  this->rcdata = rcdata;
  this->sign = sign;
}

Rpy::Rpy(bool b, RCData rcdata, Sign sign) {
  this->set   = b;
  this->rcdata = rcdata;
  this->sign = sign;
}

bool  Rpy::isSet()    { return this->set;   }
RCData Rpy::getRCData() { return this->rcdata; }
Sign Rpy::getSign() { return this->sign; }


void Rpy::serialize(salticidae::DataStream &data) const {
  data << this->set << this->rcdata << this->sign;
}


void Rpy::unserialize(salticidae::DataStream &data) {
  data >> this->set >> this->rcdata >> this->sign;
}


std::string Rpy::prettyPrint() {
  return ("RPY[" + std::to_string(this->set) + "," + (this->rcdata).prettyPrint() + "," + (this->sign).prettyPrint() + "]");
}

std::string Rpy::toString() {
  return (std::to_string(this->set) + (this->rcdata).toString() + (this->sign).toString());
}



// The view at which the certificate was generated depends on the kind of certificate we have
View Rpy::getRCView() {
  return rcdata.getPrepv();
}


Hash Rpy::getRCHash() {
  return rcdata.getPreph();
}

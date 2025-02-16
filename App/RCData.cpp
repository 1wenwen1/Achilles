#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "RCData.h"


Hash   RCData::getPreph()  { return (this->preph); }
View   RCData::getPrepv()  { return (this->prepv); }
View   RCData::getView()  { return (this->view); }
Nonce  RCData::getNonce()  { return (this->nonce); }


void RCData::serialize(salticidae::DataStream &data) const {
  data << this->preph << this->prepv << this->view << this->nonce;
}


void RCData::unserialize(salticidae::DataStream &data) {
  data >> this->preph >> this->prepv >> this->view >> this->nonce;
}


RCData::RCData(Hash preph, View prepv, View view, Nonce nonce) {
  this->preph=preph;
  this->prepv=prepv;
  this->view=view;
  this->nonce=nonce;
}


RCData::RCData() {
  this->preph=Hash();
  this->prepv=0;
  this->view=0;
  this->nonce=Nonce();
}


RCData::RCData(salticidae::DataStream &data) {
  unserialize(data);
}



std::string RCData::prettyPrint() {
  return ("RDATA[" + (this->preph).prettyPrint() 
          + "," + std::to_string(this->prepv)
          + "," + std::to_string(this->view)
          + "," + (this->nonce).prettyPrint()
          + "]");
}

std::string RCData::toString() {
  return ((this->preph).toString() + std::to_string(this->prepv)
          + std::to_string(this->view)
          + (this->nonce).toString());
}


bool RCData::operator==(const RCData& s) const {
  if (DEBUG1) {
    std::cout << KYEL
              << "[1]" << (this->preph == s.preph)
              << "[2]" << (this->prepv == s.prepv)
              << "[3]" << (this->view == s.view)
              << "[4]" << (this->nonce == s.nonce)
              << KNRM << std::endl;
  }
  return (this->preph == s.preph
          && this->prepv == s.prepv
          && this->view == s.view
          && this->nonce == s.nonce);
}

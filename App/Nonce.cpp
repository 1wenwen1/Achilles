#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <cstring>

#include "Nonce.h"


bool Nonce::getSet()  { return this->set;  }
unsigned char * Nonce::getNonce() { return this->nonce; }
bool Nonce::isDummy() { return !this->set; }

void Nonce::serialize(salticidae::DataStream &data) const {
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { data << this->nonce[i]; }
  data << this->set;
}


void Nonce::unserialize(salticidae::DataStream &data) {
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { data >> this->nonce[i]; }
  data >> this->set;
}


Nonce::Nonce() {
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { this->nonce[i] = '0'; }
  this->set=true;
}

Nonce::Nonce(bool b) {
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { this->nonce[i] = '0'; }
  this->set=b;
}


Nonce::Nonce(unsigned char nonce[RANDOM_NUMBER_LENGTH]) {
  memcpy(this->nonce,nonce,RANDOM_NUMBER_LENGTH);
  this->set=true;
}

Nonce::Nonce(bool b, unsigned char nonce[RANDOM_NUMBER_LENGTH]) {
  memcpy(this->nonce,nonce,RANDOM_NUMBER_LENGTH);
  this->set=b;
}


Nonce::Nonce(salticidae::DataStream &data) {
  unserialize(data);
  //this->set=true;
}


bool Nonce::isZero() {
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { if (this->nonce[i] != '0') { return false; } }
  return true;
}

std::string Nonce::prettyPrint() {
  return ("#" + std::to_string(this->set));
}

std::string Nonce::toString() {
  std::string text;
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { text += this->nonce[i]; }
  text += std::to_string(this->set);
  return text;
}

bool Nonce::operator==(const Nonce& s) const {
  for (int i = 0; i < RANDOM_NUMBER_LENGTH; i++) { if (nonce[i] != s.nonce[i]) { return false; } }
  return true;
}

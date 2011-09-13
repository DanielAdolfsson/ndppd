// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel.adolfsson@tuhox.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#ifndef __NDPPD_PTR_H
#define __NDPPD_PTR_H

__NDPPD_NS_BEGIN

// This template class simplifies the usage of pointers. It's basically
// a reference-counting smart-pointer that supports both weak and
// strong references.

template <typename T>
class ptr
{
private:
   struct ref
   {
   public:
      T* p;   // Pointer.
      int ns; // Number of strong references.
      int nw; // Number of weak references.
   };

   ref *_ref;
   bool _weak;

   void acquire(T* p)
   {
      if(_ref)
         release();

      if(p)
      {
         _ref     = new ref;
         _ref->p  = p;
         _ref->ns = 1;
         _ref->nw = 0;
         _weak    = false;

         // DBG("acquire(T*) p=%x, count=%d", p, 1);
      }
   }

   void acquire(const ptr<T>& p, bool weak = false)
   {
      if(_ref)
         release();

      if(p._ref && p._ref->ns)
      {
         _ref  = p._ref;
         _weak = weak;

         if(_weak)
            _ref->nw++;
         else
            _ref->ns++;

         // DBG("acquire(const ptr<T>&) p=%x, count=%d", _ref->p, _ref->count);
      }
   }

   void release()
   {
      if(!_ref)
         return;

      if(!_weak && _ref->ns)
      {
         if(!--_ref->ns && _ref->p)
         {
            delete _ref->p;
            _ref->p = 0;
         }
      }

      if(_weak)
         _ref->nw--;

      if(!_ref->ns && !_ref->nw)
         delete _ref;

      _ref = 0;
      _weak = false;
   }

public:
   ptr() :
      _ref(0), _weak(false)
   {
   }

   explicit ptr(T* p) :
      _ref(0), _weak(false)
   {
      acquire(p);
   }

   ptr(const ptr<T>& p) :
      _ref(0), _weak(false)
   {
      acquire(p, p._weak);
   }

   ptr(const ptr<T>& p, bool weak) :
      _ref(0), _weak(false)
   {
      acquire(p, weak);
   }

   ~ptr()
   {
      if(_ref)
         release();
   }

   static ptr null()
   {
      return ptr();
   }

   void operator=(T* p)
   {
      acquire(p);
   }

   void operator=(const ptr<T>& p)
   {
      acquire(p, p._weak);
   }

   bool operator==(const ptr<T>& other) const
   {
      return other._ref == _ref;
   }

   bool operator!=(const ptr<T>& other) const
   {
      return other._ref != _ref;
   }

   bool is_null() const
   {
      return !((_ref != 0) && (_ref->p != 0));
   }

   bool is_weak() const
   {
      return _weak;
   }

   bool is_strong() const
   {
      return !_weak;
   }

   ptr<T> weak_copy() const
   {
      return ptr<T>(*this, true);
   }

   ptr<T> strong_copy() const
   {
      return ptr<T>(*this, false);
   }

   T& operator*() const
   {
      return *_ref.p;
   }

   T* operator->() const
   {
      return _ref ? _ref->p : 0;
   }

   operator T*() const
   {
      return _ref->p;
   }

   operator bool() const
   {
      return !is_null();
   }

   void reset(T *p = 0)
   {
      acquire(p);
   }

};

__NDPPD_NS_END

#endif // __NDPPD_PTR_H
 
 

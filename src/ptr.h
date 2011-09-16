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

#include <stdlib.h>

__NDPPD_NS_BEGIN

// This template class simplifies the usage of pointers. It's basically
// a reference-counting smart pointer that supports both weak and
// strong references.

template <typename T>
class ptr
{
protected:
   struct ref
   {
   public:
      T* p;
      int n_strong;
      int n_weak;
   };

   ref *_ref;

   bool _strong;

   void acquire(T* p)
   {
      if(_ref)
         release();

      if(p)
      {
         _ref           = new ref;
         _ref->p        = p;
         _ref->n_strong = _strong ? 1 : 0;
         _ref->n_weak   = _strong ? 0 : 1;
      }
   }

   void acquire(const ptr<T>& p)
   {
      if(_ref)
         release();

      if(p._ref && p._ref->n_strong)
      {
         _ref = p._ref;

         if(_strong)
            _ref->n_strong++;
         else
            _ref->n_weak++;
      }
   }

   void release()
   {
      if(!_ref)
         return;

      if(_strong)
      {
         // Assert _ref->n_strong > 0.

         if(_ref->n_strong == 1)
         {
            delete _ref->p;
            _ref->p = 0;
         }

         _ref->n_strong--;
      }
      else
      {
         _ref->n_weak--;
      }

      if(!_ref->n_weak && !_ref->n_strong)
         delete _ref;

      _ref = 0;
   }

   ptr(bool strong) :
      _strong(strong), _ref(0)
   {
   }

   ptr(bool strong, T* p) :
      _strong(strong), _ref(0)
   {
      if(p)
         acquire(p);
   }

   ptr(bool strong, const ptr<T>& p) :
      _strong(strong), _ref(0)
   {
      acquire(p);
   }

   virtual ~ptr()
   {
      if(_ref)
         release();
   }

public:

   void operator=(T* p)
   {
      acquire(p);
   }

   void operator=(const ptr<T>& p)
   {
      acquire(p);
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

   bool is_strong() const
   {
      return _strong;
   }

   bool is_weak() const
   {
      return !_strong;
   }

   void reset(T *p = 0)
   {
      acquire(p);
   }
};

template <typename T>
class weak_ptr;

template <typename T>
class strong_ptr : public ptr<T>
{
public:
   strong_ptr() : ptr<T>(true)
   {
   }

   strong_ptr(T* p) : ptr<T>(true, p)
   {
   }

   strong_ptr(const ptr<T>& p) : ptr<T>(true, p)
   {
   }

   strong_ptr(const strong_ptr<T>& p) : ptr<T>(true, p)
   {
   }

   strong_ptr(const weak_ptr<T>& p) : ptr<T>(true, p)
   {
   }
};

template <typename T>
class weak_ptr : public ptr<T>
{
public:
   weak_ptr() : ptr<T>(false)
   {
   }

   weak_ptr(T* p) : ptr<T>(false, p)
   {
   }

   weak_ptr(const ptr<T>& p) : ptr<T>(false, p)
   {
   }

   weak_ptr(const strong_ptr<T>& p) : ptr<T>(false, p)
   {
   }

   weak_ptr(const weak_ptr<T>& p) : ptr<T>(false, p)
   {
   }
};

__NDPPD_NS_END

#endif // __NDPPD_PTR_H

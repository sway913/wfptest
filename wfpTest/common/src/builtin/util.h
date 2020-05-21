// Copyright (c) 2020 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include "common.h"
#line HEADER_FILE("builtin/util.h")

#ifndef BUILTIN_UTIL_H
#define BUILTIN_UTIL_H
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <type_traits>
#include <assert.h>
#include <chrono>


#if defined(Q_COMPILER_TEMPLATE_AUTO)
#define TEMPLATE_AUTO_DECL(name)     auto name
#define TEMPLATE_AUTO(value)         value
#define TEMPLATE_AUTO_DECLTYPE(name) decltype(name)
#else
#define TEMPLATE_AUTO_DECL(name)     typename CONCAT(TYPE_,name), CONCAT(TYPE_,name) name
#define TEMPLATE_AUTO(value)         decltype(value), value
#define TEMPLATE_AUTO_DECLTYPE(name) CONCAT(TYPE_,name)
#endif

class Error;

class noncopyable;
class nonmovable;
template<typename Handle> class raii_dynamic_t;
template<typename Handle, Handle Null = 0> class raii_dynamic_nullable_t;
template<typename Handle, typename FreeFnType, FreeFnType FreeFn> class raii_static_t;
template<typename Handle, typename FreeFnType, FreeFnType FreeFn, Handle Null = 0> class raii_static_nullable_t;


// Helper base class to force subclass to be noncopyable.
//
class COMMON_EXPORT noncopyable
{
    noncopyable(const noncopyable&) = delete;
    noncopyable& operator=(const noncopyable&) = delete;
protected:
    noncopyable() {}
};

// Helper base class to force subclass to be nonmovable.
//
class COMMON_EXPORT nonmovable
{
    nonmovable(nonmovable&&) = delete;
    nonmovable& operator=(nonmovable&&) = delete;
protected:
    nonmovable() {}
};


template<typename T>
class nullable_t;

template<typename T>
struct get_nullable;

/*
template<typename T> static inline nullable_t<T> make_nullable(T&& value);
template<typename T> static inline T* make_nullable(T* ptr) { return ptr; }
template<typename T, typename D> static inline std::shared_ptr<T, D> make_nullable(std::shared_ptr<T, D> ptr) { return ptr; }
template<typename T, typename D> static inline std::unique_ptr<T, D> make_nullable(std::shared_ptr<T, D> ptr) { return ptr; }
*/

template<typename Handle, typename FreeFnType = int, FreeFnType... FreeFn>
class raii_t;


template<typename Class, typename Ptr, typename Return, typename... Args>
static inline auto bind_this(Return (Class::*fn)(Args...), Ptr instance)
{
    return [instance = std::move(instance), fn](Args&&... args) -> Return { return ((*instance).*fn)(std::forward<Args>(args)...); };
}
template<typename Class, typename Ptr, typename... Args>
static inline auto bind_this(void (Class::*fn)(Args...), Ptr instance)
{
    return [instance = std::move(instance), fn](Args&&... args) { ((*instance).*fn)(std::forward<Args>(args)...); };
}


namespace impl {

template<typename Handle>
class wrapped_handle
{
    Handle _handle;
    template<typename H, typename F, F... Fs> friend class raii_t;
    template<typename FreeFnType, FreeFnType... FreeFn> friend class raii_static_helper;
public:
    wrapped_handle(Handle handle) : _handle(std::move(handle)) {}
};


template<typename T =
         #ifdef Q_OS_WIN
         unsigned long
         #else
         int
         #endif
         >
class check_error_holder
{
    T _error;
public:
    check_error_holder(const std::nullptr_t&) {}
    void set(T error) { _error = std::move(error); }
    operator bool() const { return true; }
    T& error() { return _error; }
};


// Remove the Nth type in a tuple
template<size_t N, typename Tuple>
struct remove_nth_type;

template<typename T, typename... Ts>
struct remove_nth_type<0, std::tuple<T, Ts...>> { typedef std::tuple<Ts...> type; };

template<size_t N, typename T, typename... Ts>
struct remove_nth_type<N, std::tuple<T, Ts...>> { typedef decltype(std::tuple_cat(std::declval<std::tuple<T>>(), std::declval<typename remove_nth_type<N - 1, std::tuple<Ts...>>::type>())) type; };


// Split a tuple around the Nth type into left, middle and right
template<size_t N, typename Tuple>
struct split_tuple;

template<typename T, typename... Ts>
struct split_tuple<0, std::tuple<T, Ts...>> { typedef std::tuple<> left; typedef T middle; typedef std::tuple<Ts...> right; };

template<size_t N, typename T, typename... Ts>
struct split_tuple<N, std::tuple<T, Ts...>>
{
    typedef split_tuple<N - 1, std::tuple<Ts...>> inner;
    typedef decltype(std::tuple_cat(std::declval<std::tuple<T>>(), std::declval<typename inner::left>())) left;
    typedef typename inner::middle middle;
    typedef typename inner::right right;
};


// Implementation of callback wrapper
template<typename ContextArgType, typename Return, typename PrefixArgsTuple, typename InnerArgsTuple>
class callback_impl;

template<typename ContextArgType, typename Return, typename... LeftArgs, typename... RightArgs>
class callback_impl<ContextArgType, Return, std::tuple<LeftArgs...>, std::tuple<RightArgs...>> : public std::function<Return(LeftArgs..., RightArgs...)>
{
    typedef std::function<Return(LeftArgs..., RightArgs...)> base;

public:
    using base::base;
    using base::operator=;

    static_assert(sizeof(ContextArgType) == sizeof(void*) && (std::is_convertible<void*, ContextArgType>::value || std::is_convertible<ContextArgType, uintptr_t>::value), "unrecognized context argument type");

#   define IMPLEMENT_CALLING_CONVENTION(...) \
    typedef Return(__VA_ARGS__ *CONCAT(__VA_ARGS__,Signature))(LeftArgs... left, ContextArgType ctx, RightArgs... right); \
    static Return __VA_ARGS__ CONCAT(__VA_ARGS__,_thunk)(LeftArgs... left, ContextArgType ctx, RightArgs... right) { return fn(ctx)(left..., right...); } \
    operator CONCAT(__VA_ARGS__,Signature)() { return CONCAT(__VA_ARGS__,_thunk); }

    ITERATE_CALLING_CONVENTIONS(IMPLEMENT_CALLING_CONVENTION)

#   undef IMPLEMENT_CALLING_CONVENTION

    operator void*() { return reinterpret_cast<void*>(this); }
    operator intptr_t() { return reinterpret_cast<intptr_t>(this); }
    operator uintptr_t() { return reinterpret_cast<uintptr_t>(this); }

protected:
    static base& fn(ContextArgType ctx) { return *static_cast<base*>(reinterpret_cast<callback_impl*>(ctx)); }
};


// Helper template alias for base class below
template<size_t ContextArgIndex, typename Return, typename... Args>
using select_callback_impl = callback_impl<
        typename split_tuple<ContextArgIndex, std::tuple<Args...>>::middle,
        Return,
        typename split_tuple<ContextArgIndex, std::tuple<Args...>>::left,
        typename split_tuple<ContextArgIndex, std::tuple<Args...>>::right
>;

}

template<typename T, typename U> static inline bool operator==(const nullable_t<T>& a, const nullable_t<U>& b) { return a ? b && *a == *b : !b; }
template<typename T, typename U> static inline bool operator!=(const nullable_t<T>& a, const nullable_t<U>& b) { return a ? !b || *a != *b : !!b; }

template<typename T, typename U> static inline bool operator==(const nullable_t<T>& a, const U& b) { return a && *a == b; }
template<typename T, typename U> static inline bool operator==(const U& b, const nullable_t<T>& a) { return a && *a == b; }
template<typename T, typename U> static inline bool operator!=(const nullable_t<T>& a, const U& b) { return !a || *a != b; }
template<typename T, typename U> static inline bool operator!=(const U& b, const nullable_t<T>& a) { return !a || *a != b; }

template<typename T> static inline bool operator==(const nullable_t<T>& a, const std::nullptr_t&) { return !a; }
template<typename T> static inline bool operator==(const std::nullptr_t&, const nullable_t<T>& a) { return !a; }
template<typename T> static inline bool operator!=(const nullable_t<T>& a, const std::nullptr_t&) { return !!a; }
template<typename T> static inline bool operator!=(const std::nullptr_t&, const nullable_t<T>& a) { return !!a; }

// Helper template to get an appropriate nullable type for a type T.
//
template<typename T> struct get_nullable { typedef nullable_t<T> type; };
template<typename T> struct get_nullable<T*> { typedef T* type; };
template<typename T> struct get_nullable<nullable_t<T>> { typedef nullable_t<T> type; };
template<typename T> using get_nullable_t = typename get_nullable<T>::type;

template<typename T> using Nullable = get_nullable_t<T>;
template<typename T> using Optional = get_nullable_t<T>;

// Convenience macro to schedule a block of code (actually a lambda) to run
// at the end of the current scope. If multiple sentinels are listed in the
// same scope, they will run in reverse order.
//
#define RAII_SENTINEL(...) auto CONCAT(_raii_sentinel_,__LINE__) = raii_sentinel([&](){ __VA_ARGS__; })
#define FINALLY RAII_SENTINEL
#define CLEANUP RAII_SENTINEL
#define AT_SCOPE_EXIT RAII_SENTINEL



// Lightweight RAII handle class, type-bound to a free function at compile
// time for the smallest possible overhead.
//
template<typename Handle, typename FreeFnType, FreeFnType FreeFn>
class raii_t<Handle, FreeFnType, FreeFn>
{
    typedef get_nullable_t<Handle> NullableHandle;
    NullableHandle _handle;
    template<typename H, typename F, F...> friend class raii_t;
public:
    raii_t() {}
    explicit raii_t(Handle handle) : _handle(std::move(handle)) {}
    raii_t(const raii_t& copy) = delete;
    raii_t& operator=(const raii_t& copy) = delete;
    raii_t(raii_t&& move) : _handle(std::exchange(move._handle, nullptr)) {}
    raii_t& operator=(raii_t& move) { if (_handle != nullptr) FreeFn(std::exchange(_handle, nullptr)); _handle = std::exchange(move._handle, nullptr); return *this; }
    ~raii_t() { if (_handle != nullptr) FreeFn(std::exchange(_handle, nullptr)); }

    // Typed variables can be assigned to from a wrapped handle that
    // has no defined free function of its own.
    raii_t(::impl::wrapped_handle<Handle>&& move) : _handle(std::move(move._handle)) {}
    raii_t& operator=(::impl::wrapped_handle<Handle>&& move) { if (_handle != nullptr) FreeFn(std::exchange(_handle, nullptr)); _handle = std::move(move._handle); return *this; }

    operator Handle() const { return _handle; }
    template<typename PointerHandle = Handle> std::enable_if_t<std::is_pointer<PointerHandle>::value, PointerHandle> operator->() { return _handle; }
    bool valid() const { return _handle != nullptr; }
    Handle detach() { return std::exchange(_handle, nullptr); }
};

// Lightweight RAII handle class, where the free function is of a known
// type but is assigned at runtime. Mainly useful for lambdas or functors
// which cannot be part of a type signature.
//
template<typename Handle, typename FreeFnType>
class raii_t<Handle, FreeFnType>
{
    typedef get_nullable_t<Handle> NullableHandle;
    NullableHandle _handle;
    FreeFnType _free;
    template<typename H, typename F, F...> friend class raii_t;
public:
    raii_t() {}
    explicit raii_t(Handle handle, FreeFnType free) : _handle(std::move(handle)), _free(std::move(free)) {}
    raii_t(const raii_t& copy) = delete;
    raii_t& operator=(const raii_t& copy) = delete;
    raii_t(raii_t&& move) : _handle(std::exchange(move._handle, nullptr)), _free(std::move(move._free)) {}
    raii_t& operator=(raii_t&& move) { if (_handle != nullptr) _free(std::exchange(_handle, nullptr)); _handle = std::exchange(move._handle, nullptr); _free = std::move(move._free); return *this; }
    ~raii_t() { if (_handle != nullptr) _free(std::exchange(_handle, nullptr)); }

    operator Handle() const { return _handle; }
    template<typename PointerHandle = Handle> std::enable_if_t<std::is_pointer<PointerHandle>::value, PointerHandle> operator->() { return _handle; }
    bool valid() const { return _handle != nullptr; }
    Handle detach() { return std::exchange(_handle, nullptr); }
};

// Lightweight RAII handle class, where the free function is of a known
// type but is assigned at runtime. Mainly useful for lambdas or functors
// which cannot be part of a type signature. Specialization for function
// pointer based free functions.
//
template<typename Handle, typename FreeFnType>
class raii_t<Handle, FreeFnType*>
{
    Handle _handle;
    FreeFnType* _free;
    template<typename H, typename F, F...> friend class raii_t;
public:
    raii_t() {}
    explicit raii_t(Handle handle, FreeFnType* free) : _handle(std::move(handle)), _free(free) {}
    raii_t(const raii_t& copy) = delete;
    raii_t& operator=(const raii_t& copy) = delete;
    raii_t(raii_t&& move) : _handle(std::move(move._handle)), _free(std::exchange(move._free, nullptr)) {}
    raii_t& operator=(raii_t&& move) { if (_free) std::exchange(_free, nullptr)(_handle); _handle = std::move(move._handle); _free = std::exchange(move._free, nullptr); return *this; }
    ~raii_t() { if (_free) std::exchange(_free, nullptr)(_handle); }

    operator Handle() const { return _handle; }
    template<typename PointerHandle = Handle> std::enable_if_t<std::is_pointer<PointerHandle>::value, PointerHandle> operator->() { return _handle; }
    bool valid() const { return _free != nullptr; }
    Handle detach() { _free = nullptr; return _handle; }
};


// Lightweight RAII handle class, where the free function is of a known
// type but is assigned at runtime and stored in a generic std::function
// object. This is the most general version of the class, and is assignable
// from any of the other specializations.
//
template<typename Handle, int... dummy>
class raii_t<Handle, int, dummy...>
{
    Handle _handle;
    std::function<void(Handle&)> _free;
    template<typename H, typename F, F...> friend class raii_t;
public:
    raii_t() {}
    template<typename FreeFnType>
    explicit raii_t(Handle handle, FreeFnType&& free) : _handle(std::move(handle)), _free(std::forward<FreeFnType>(free)) {}
    raii_t(const raii_t& copy) = delete;
    raii_t& operator=(const raii_t& copy) = delete;
    raii_t(raii_t&& move) : _handle(std::move(move._handle)), _free(std::exchange(move._free, nullptr)) {}
    raii_t& operator=(raii_t&& move) { if (_free) std::exchange(_free, nullptr)(_handle); _handle = std::move(move._handle); _free = std::exchange(move._free, nullptr); return *this; }
    ~raii_t() { if (_free) std::exchange(_free, nullptr)(_handle); }

    // Dynamic RAII wrappers can also be constructed or assigned from static
    // RAII wrappers, by wrapping the free function in a std::function and
    // checking the handle value for nullptr.
    template<typename FreeFnType, FreeFnType FreeFn>
    raii_t(raii_t<Handle, FreeFnType, FreeFn>&& move) { if (move._handle != nullptr) { _handle = std::exchange(move._handle, nullptr); _free = FreeFn; } }
    template<typename FreeFnType, FreeFnType FreeFn>
    raii_t& operator=(raii_t<Handle, FreeFnType, FreeFn>&& move) { if (_free) std::exchange(_free, nullptr)(_handle); if (move._handle != nullptr) { _handle = std::exchange(move._handle, nullptr); _free = FreeFn; } return *this; }
    template<typename FreeFnType>
    raii_t(raii_t<Handle, FreeFnType>&& move) { if (move._handle != nullptr) { _handle = std::exchange(move._handle, nullptr); _free = std::move(move._free); } }
    template<typename FreeFnType>
    raii_t& operator=(raii_t<Handle, FreeFnType>&& move) { if (_free) std::exchange(_free, nullptr)(_handle); if (move._handle != nullptr) { _handle = std::exchange(move._handle, nullptr); _free = std::move(move._free); } return *this; }
    template<typename FreeFnType>
    raii_t(raii_t<Handle, FreeFnType*>&& move) { if (move._free != nullptr) { _handle = std::move(move._handle); _free = std::exchange(move._free, nullptr); } }
    template<typename FreeFnType>
    raii_t& operator=(raii_t<Handle, FreeFnType*>&& move) { if (_free) std::exchange(_free, nullptr)(_handle); if (move._free != nullptr) { _handle = std::move(move._handle); _free = std::exchange(move._free, nullptr); } }

    operator Handle() const { return _handle; }
    template<typename PointerHandle = Handle> std::enable_if_t<std::is_pointer<PointerHandle>::value, PointerHandle> operator->() { return _handle; }
    bool valid() const { return _free != nullptr; }
    Handle detach() { _free = nullptr; return _handle; }
};


// Macro that expands to a RAII wrapper class type with an optional statically
// bound free function. If the free function is omitted, this becomes a dynamic
// RAII wrapper that instead gets the free function as a constructor argument.
//
#define RAII(type, ...) raii_t<type, decltype(::impl::raii_free_helper(__VA_ARGS__)),##__VA_ARGS__>

// Macro to wrap a handle into an RAII class with the free function
// statically typed in. This works for named functions but not for lambdas
// or functors. The free function can be omitted, but the resulting handle
// must then be assigned to a statically typed RAII(type, free) variable.
//
#define RAII_WRAP(handle, ...) ::impl::raii_static_helper<decltype(::impl::raii_free_helper(__VA_ARGS__)),##__VA_ARGS__>::make(handle)

// Function to wrap a handle into an RAII class with the free function
// dynamically bound to a typed instance. Use this when RAII_WRAP() fails to
// compile, such as when you need functors or lambdas as a free function.
//
template<typename Handle, typename FreeFnType>
static inline auto raii_wrap(Handle&& handle, FreeFnType&& free) { return raii_t<Handle, FreeFnType>(std::forward<Handle>(handle), std::forward<FreeFnType>(free)); }



// A lightweight framework to handle errors in an exception-like
// fashion, but local to the current function (e.g. when calling
// a lot of platform APIs and wanting to bail out of a sequence
// early when an error is encountered). C++ scopes are respected
// allowing RAII style resource handling.
//
// Usage:
//   LOCAL_TRY(int)
//   {
//       if (!callFunction())
//           LOCAL_THROW(errno);
//       return true;
//   }
//   LOCAL_CATCH(error)
//   {
//       qWarning() << "Got error" << error;
//       return false;
//   }
//
// Notes:
// - You can have at most one LOCAL_TRY block in a function.
//
#define LOCAL_TRY(...) if (::impl::check_error_holder<__VA_ARGS__> _local_error_holder = nullptr)
#define LOCAL_THROW(error) do { _local_error_holder.set(error); goto _local_error_exit; } while(0)
#define LOCAL_CATCH(var) else _local_error_exit: if (bool _local_error_guard = false) {} else for (auto& var = _local_error_holder.error(); !_local_error_guard; _local_error_guard = true) if (const bool _local_error_holder = false) {} else



// Evaluates to the class type of the current 'this' pointer
#define THIS_CLASS std::decay_t<decltype(*this)>
// Creates a closure of a member function, taking the same arguments
#define THIS_FUNCTION(name) ::bind_this(&THIS_CLASS::name, this)


// Wrapper for passing an arbitrary std::function to a platform
// function that takes a callback function pointer plus context
// pointer. The position of the context pointer in the callback
// parameter list is passed as the second template parameter,
// and is spliced out of the parameter list passed to the inner
// callable.
//
// Usage:
//   extern void callCallback(void(*fn)(void*), void* ctx);
//   callback<void(void*), 0> cb = [&]() { /* ... */ };
//   callCallback(cb, cb);
//
template<typename Signature, size_t ContextArgIndex = 0>
class callback_signature_t;

#define IMPLEMENT_CALLBACK(...) \
    template<size_t ContextArgIndex, typename Return, typename... Args> \
    class callback_signature_t<Return __VA_ARGS__ (Args...), ContextArgIndex> : public ::impl::select_callback_impl<ContextArgIndex, Return, Args...> \
    { \
        typedef ::impl::select_callback_impl<ContextArgIndex, Return, Args...> base; \
    public: \
        using base::base; \
        using base::operator=; \
    };

ITERATE_CALLING_CONVENTIONS(IMPLEMENT_CALLBACK)

#undef IMPLEMENT_CALLBACK


template<typename Signature, size_t ContextArgIndex = 0>
using callback_t = callback_signature_t<std::remove_pointer_t<Signature>, ContextArgIndex>;

// Base class to implement the singleton pattern; used for classes for which
// there should only be a single instance. The class must still be manually
// instantiated (on the heap or on the stack), upon which its instance will
// be tracked by the class. To instantiate the singleton on the heap, it is
// sufficient to simply call `new Derived(...)` - the result does not need
// to be assigned anywhere.
//
// Singleton is _not_ thread-safe.  A thread-safe singleton class should define
// its own static mutex and _instance pointer.  (Note that locking a mutex in
// the Singleton constructor and in Singleton::instance() would not be
// sufficient; there would be no guarantee that an object returned by
// Singleton::instance() was still valid at the point of use.)
//
// NOTE: This template contains a static member in a dynamic library.  If a
// specialization of this template might be used by both code in common and in
// the linking executable, Singleton::_instance _must_ be explicitly
// instantiated and exported (to ensure that both common and the executable link
// to the same _instance member).
//
// For example, consider a Service type derived from Singleton<Service>.  Both
// Service (in common) and the executable can call Service::instance() (actually
// Singleton<Service>::instance()).  Singleton<Service>:_instance must be
// exported:
//    service.h:
//       extern template class COMMON_EXPORT_TMPL_SPEC_DECL Singleton<Service>;
//    service.cpp:
//       template class COMMON_EXPORT Singleton<Service>;
//
// If instantiating the template in a module other than common, use the
// appropriate annotations for that module.   COMMON_EXPORT_TMPL_SPEC_DECL is
// used to work around strange behavior in MSVC specifically for this type of
// exported template specialization.
template<class Derived>
class Singleton
{
public:
    Singleton() { assert(_instance == nullptr); _instance = this; }
    ~Singleton() { _instance = nullptr; }
    static Derived* instance() { return static_cast<Derived*>(_instance); }
private:
    static Singleton* _instance;
};

template<class Derived>
Singleton<Derived>* Singleton<Derived>::_instance = nullptr;

// Base class to implement the singleton pattern by having the class
// instantiate itself on the heap automatically. To explicitly delete
// the singleton instance, use `delete Derived::instance()`.
//
template<class Derived>
class AutoSingleton : public Singleton<Derived>
{
public:
    static Derived* instance() { if (auto i = Singleton<Derived>::instance()) return i; else return new Derived(); }
};


namespace impl {
    // This cheekily borrows straight from Qt internals, but it was the only
    // way to provide this functionality in a SFINAE friendly manner.
    static inline const char* qTypeName(...) { return nullptr; }
}

// Helper to read out the type name of a type, if known to Qt, or nullptr otherwise.
template<typename T>
static inline const char* qTypeName() { return impl::qTypeName(static_cast<T*>(nullptr)); }

// Millsecond count from a duration as a qint64.  (Can be used with any
// duration units thanks to implicit conversions.)
//
// This is the preferred way to use durations with QTimer, since Qt doesn't
// provide the duration overloads of QTimer methods on all platforms we support.
//
// msec() returns the full count as a qint64 (std::chrono::milliseconds has at
// least 45 bits of precision).  msec32() truncates to 32-bit for use with
// QTimer.
//
// Consider:
//     std::chrono::milliseconds shortInterval(500);
//     std::chrono::minutes longInterval(2);
//
// Error-prone:
//     _timer.setInterval(shortInterval.count());  // OK
//     _timer.setInterval(longInterval.count());  // WRONG!  Sets to 2 ms
//
// Better:
//     _timer.setInterval(msec32(shortInterval));  // OK
//     _timer.setInterval(msec32(longInterval));  // OK
inline int64_t msec(const std::chrono::milliseconds &time)
{
    return static_cast<int64_t>(time.count());
}
inline __int64 msec32(const std::chrono::milliseconds &time)
{
	int64_t count = msec(time);
 //   assert(count >= std::numeric_limits<int32_t>::min());
	//assert(count <= std::numeric_limits<int32_t>::max());
    return static_cast<int32_t>(count);
}


#endif // BUILTIN_UTIL_H

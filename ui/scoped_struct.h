/**
 * @file scoped_struct.h
 * @brief Helper template for scoped structures on a function stack
 *
 * Copyright 2022 Leon Lynch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SCOPED_STRUCT_H
#define SCOPED_STRUCT_H

/**
 * This helper template can be used to ensure that structures on a function
 * stack are destroyed using an appropriate destruction function whenever they
 * go out of scope. This is different from std::unique_ptr<> which is intended
 * for pointers to dynamically allocated objects, while this template is
 * exclusively for stack objects. However, the primary reason for not using
 * std::unique_ptr<> is because std::make_unique<>() does not support a custom
 * deleter function, which in turn implies that the declaration and
 * initialization of the stack object cannot be separated.
 */
template<typename T, void (destroy_func)(T*)>
struct scoped_struct {
	T t;

	scoped_struct() : t() {}; // Ensure that t is not uninitialized
	~scoped_struct() { destroy_func(&t); }

	// Accessor helpers
	const T* get() const noexcept { return &t; }
	T* get() noexcept { return &t; }
	const T* operator->() const noexcept { return get(); }
	T* operator->() noexcept { return get(); }

	// Disallow copying and moving
	scoped_struct(scoped_struct&) = delete;
	scoped_struct(scoped_struct&&) = delete;
	scoped_struct& operator=(scoped_struct&) = delete;

	// Disallow dynamic allocation
	static void* operator new(std::size_t) = delete;
	static void* operator new[](std::size_t) = delete;
	static void operator delete(void*) = delete;
	static void operator delete[](void*) = delete;
};

#endif

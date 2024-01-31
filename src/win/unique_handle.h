#pragma once

#define UNIQUE_HANDLE_TRAITS(name, type, null_value, close_func) \
	struct name \
	{ \
		typedef type handle_t; \
		inline static handle_t NullHandle() { return null_value; } \
		inline static void Close(handle_t handle) { close_func(handle); } \
	};

#define UNIQUE_HANDLE_DECL(name, type, null_value, close_func) \
	UNIQUE_HANDLE_TRAITS(name##_traits, type, null_value, close_func) \
	typedef unique_handle<name##_traits> name;

//struct traits
//{
//	typedef HANDLE handle_t;
//	static handle_t NullHandle() { return 0; }
//	static void Close(handle_t handle) { close(handle); }
//};

namespace cryptx
{
	template <class traits>
	class unique_handle
	{
	public:
		typedef typename traits::handle_t handle_t;

		unique_handle() : m_Handle(traits::NullHandle()) {}

		unique_handle(handle_t handle)
			: m_Handle(handle) {}

		unique_handle(unique_handle<traits>&& other)
			: m_Handle(other.m_Handle)
		{
			other.m_Handle = traits::NullHandle();
		}

		unique_handle(const unique_handle<traits>& other) = delete;

		~unique_handle()
		{
			reset();
		}

		operator bool() const
		{
			return traits::NullHandle() != m_Handle;
		}

		bool operator!() const
		{
			return traits::NullHandle() == m_Handle;
		}

		handle_t* operator&() { return &m_Handle; }

		unique_handle& operator=(unique_handle&& other)
		{
			reset();
			std::swap(m_Handle, other.m_Handle);
			return *this;
		}

		unique_handle& operator=(const unique_handle& other) = delete;

		void reset(handle_t new_handle = traits::NullHandle())
		{
			if (m_Handle != traits::NullHandle())
				traits::Close(m_Handle);
			m_Handle = new_handle;
		}

		handle_t get() const { return m_Handle; }

		handle_t release() { auto handle = m_Handle; m_Handle = traits::NullHandle(); return handle; }

	private:
		handle_t m_Handle;
	};
}
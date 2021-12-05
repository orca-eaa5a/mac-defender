#pragma once
#ifndef _RSIG_WRAPPER_
#define _RSIG_WRAPPER_

#include <stdio.h>
#include <string>
#include <functional>
#include <windows.h>

#include "cb/cb.h"
#include "mpcore/engineboot.h"
#include "mpcore/openscan.h"
#include "mpcore/rsignal.h"
#include "mpcore/streambuffer.h"
#include "log.hpp"

#define _ZEROMEMORY_(buf, sz) memset(buf, 0, sz)

using namespace std;


class RsignalWrapper {
	typedef unsigned int(_cdecl * __rsignal)(void** hKrnl, unsigned int flag, void* bootOption, unsigned int size);
	typedef uint64_t(_cdecl * notify_cb)(SCAN_REPLY* scan_reply);

private:
	ENGINE_CONFIG engine_config;
	StreamBufferScanData scan_params;
	CCftScanState scan_state;
	BOOTENGINE_PARAMS boot_params;
	StreamBufferDescriptor stream_buffer_descriptor;
	ENGINE_INFO engine_info;
public:
	__rsignal _rsignal = nullptr;
	notify_cb cb = nullptr;
	wstring signature_location;
	void* kernel_handle;
	function<void(void*)> set_notify_cb = [this](void* cb) {
		this->cb = (notify_cb)cb;
		this->scan_state.ClientNotifyCallback = this->cb;
	};
	function<void(void*)> set_rsignal = [this](void* rsignal_addr) {
		this->_rsignal = (__rsignal)rsignal_addr;
	};
	function<void(std::string)> set_vdm_location = [this](string loc) {
		this->signature_location.assign(loc.begin(), loc.end());
		this->boot_params.SignatureLocation = (wchar_t*)signature_location.c_str();
	};

	function<void(void)> rsig_boot_engine = [this]() {
		if (this->signature_location.empty()) {
			console_log(MSGTYPE::CRIT, "Please set signature location first, show RsignalWrapper::set_vdm_location");
			return false;
		}
		uint32_t res = this->_rsignal(
			&this->kernel_handle,
			RSIG_BOOTENGINE,
			&this->boot_params,
			sizeof(BOOTENGINE_PARAMS)
		);

		if (res) {
			if (res >= 32700 && res < 40000) {
				console_log(MSGTYPE::ERR, "Error occured by invalid parameter");
				console_log(MSGTYPE::INFO, "Check the parameter version or it's structure");
			}
			else if (res >= 40000) {
				console_log(MSGTYPE::ERR, "Error occured by invalid mpengine core version");
				console_log(MSGTYPE::INFO, "Check that mpengine and signature database version match correctly");
			}
			else {
				console_log(MSGTYPE::ERR, "Unknown error");
			}
			return false;
		}
		return true;
	};

	function<void(int)> rsig_scan_stream = [this](int fp) {
		if (this->cb == nullptr) {
			console_log(MSGTYPE::INFO, "Please set notify callback first");
			return false;
		}
		this->stream_buffer_descriptor.UserPtr = fp;
		uint32_t res = this->_rsignal(
			&this->kernel_handle,
			RSIG_SCAN_STREAMBUFFER,
			&this->scan_params,
			sizeof(StreamBufferScanData)
		);
		return true;
	};

	RsignalWrapper() {
		_ZEROMEMORY_(&this->engine_config, sizeof(ENGINE_CONFIG));
		_ZEROMEMORY_(&this->scan_params, sizeof(StreamBufferScanData));
		_ZEROMEMORY_(&this->scan_state, sizeof(CCftScanState));
		_ZEROMEMORY_(&this->boot_params, sizeof(BOOTENGINE_PARAMS));
		_ZEROMEMORY_(&this->stream_buffer_descriptor, sizeof(StreamBufferDescriptor));
		_ZEROMEMORY_(&this->engine_info, sizeof(ENGINE_INFO));
		this->kernel_handle = nullptr;

		this->stream_buffer_descriptor.Read = ReadStreamCb;
		this->stream_buffer_descriptor.GetSize = GetStreamSizeCb;
		this->stream_buffer_descriptor.GetName = GetStreamNameCb;

		this->scan_params.ScanState = &this->scan_state;
		this->scan_state.ScanFlag = SCAN_VIRUSFOUND | 0xFFFFFFF; // scan all
		this->scan_state.ClientNotifyCallback = nullptr;
		this->scan_params.Descriptor = &this->stream_buffer_descriptor;

		this->engine_config.EngineFlags = 1;
		this->boot_params.ClientVersion = BOOTENGINE_PARAMS_VERSION;
		this->boot_params.EngineInfo = &this->engine_info;
		this->boot_params.EngineConfig = &this->engine_config;
		this->boot_params.SignatureLocation = nullptr;
	};
};

#endif
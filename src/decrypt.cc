#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <nan.h>

using namespace std;
using namespace v8;

HRESULT DecryptHelper(_In_reads_bytes_(cbData) BYTE* pbData, DWORD cbData, _In_ HCRYPTKEY hPrvKey, _Outptr_result_bytebuffer_(*pcbPlain) BYTE** ppbPlain, _Out_ DWORD* pcbPlain);
HRESULT ReadFileToByteArray(_In_ PCWSTR pszPath, _Outptr_result_bytebuffer_(*pcbData) BYTE** ppbData, _Out_ DWORD* pcbData);

__inline HRESULT ResultFromKnownLastError() { const DWORD err = GetLastError(); return err == ERROR_SUCCESS ? E_FAIL : HRESULT_FROM_WIN32(err); }

__inline HRESULT ResultFromWin32Bool(BOOL b)
{
    return b ? S_OK : ResultFromKnownLastError();
}

HRESULT WriteByteArrayToFile(_In_ PCWSTR pszPath, _In_reads_bytes_(cbData) BYTE const* pbData, DWORD cbData)
{
    bool fDeleteFile = false;
    HANDLE hFile = CreateFile(pszPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    HRESULT hr = (hFile == INVALID_HANDLE_VALUE) ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
    if (SUCCEEDED(hr))
    {
        DWORD cbWritten;
        hr = WriteFile(hFile, pbData, cbData, &cbWritten, nullptr) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
        fDeleteFile = FAILED(hr);
        CloseHandle(hFile);
    }

    if (fDeleteFile)
    {
        DeleteFile(pszPath);
    }
    return hr;
}

HRESULT UseSymmetricKeyFromFileToDecrypt(_In_ PCWSTR pszDataFilePath, _In_ PCWSTR pszSessionKeyPath, _In_ PCWSTR pszPrivateKeyPath)
{
    HCRYPTPROV hProv;
    HRESULT hr = CryptAcquireContext(&hProv, L"OEMDecryptContainer", MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    if (hr == NTE_EXISTS)
    {
        hr = CryptAcquireContext(&hProv, L"OEMDecryptContainer", MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }

    if (SUCCEEDED(hr))
    {
        BYTE* pbPrvBlob;
        DWORD cbPrvBlob;
        hr = ReadFileToByteArray(pszPrivateKeyPath, &pbPrvBlob, &cbPrvBlob);
        if (SUCCEEDED(hr))
        {
            HCRYPTKEY hKey;
            hr = CryptImportKey(hProv, pbPrvBlob, cbPrvBlob, 0, 0, &hKey) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
            if (SUCCEEDED(hr))
            {
                BYTE* pbSymBlob;
                DWORD cbSymBlob;
                hr = ReadFileToByteArray(pszSessionKeyPath, &pbSymBlob, &cbSymBlob);
                if (SUCCEEDED(hr))
                {

                    HCRYPTKEY hSymKey;
                    hr = CryptImportKey(hProv, pbSymBlob, cbSymBlob, hKey, 0, &hSymKey) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                    {
                        BYTE* pbCipher;
                        DWORD dwCipher;
                        hr = ReadFileToByteArray(pszDataFilePath, &pbCipher, &dwCipher);
                        if (SUCCEEDED(hr))
                        {
                            BYTE* pbPlain;
                            DWORD dwPlain;
                            hr = DecryptHelper(pbCipher, dwCipher, hSymKey, &pbPlain, &dwPlain);
                            if (SUCCEEDED(hr))
                            {
                                hr = WriteByteArrayToFile(L"plaindata.xml", pbPlain, dwPlain);
                                HeapFree(GetProcessHeap(), 0, pbPlain);
                            }
                            HeapFree(GetProcessHeap(), 0, pbCipher);
                        }
                        CryptDestroyKey(hSymKey);
                    }
                    HeapFree(GetProcessHeap(), 0, pbSymBlob);
                }
                else if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
                {
                    wcout << L"Couldn't find session key file [" << pszSessionKeyPath << L"]" << endl;
                }
                CryptDestroyKey(hKey);
            }
            HeapFree(GetProcessHeap(), 0, pbPrvBlob);
        }
        else if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        {
            wcout << L"Couldn't find private key file [" << pszPrivateKeyPath << L"]" << endl;
        }
        CryptReleaseContext(hProv, 0);
    }
    return hr;
}

HRESULT DecryptHelper(_In_reads_bytes_(cbData) BYTE* pbData, DWORD cbData, _In_ HCRYPTKEY hPrvKey, _Outptr_result_bytebuffer_(*pcbPlain) BYTE** ppbPlain, _Out_ DWORD* pcbPlain)
{
    BYTE* pbCipher = reinterpret_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cbData));
    HRESULT hr = (pbCipher != nullptr) ? S_OK : E_OUTOFMEMORY;
    if (SUCCEEDED(hr))
    {

        DWORD cbPlain = cbData;
        memcpy(pbCipher, pbData, cbData);
        hr = ResultFromWin32Bool(CryptDecrypt(hPrvKey,
            0,
            TRUE,
            0,
            pbCipher,
            &cbPlain));
        if (SUCCEEDED(hr))
        {
            *ppbPlain = pbCipher;
            *pcbPlain = cbPlain;
            pbCipher = nullptr;
        }
        HeapFree(GetProcessHeap(), 0, pbCipher);
    }    return hr;
}

HRESULT ReadFileToByteArray(_In_ PCWSTR pszPath, _Outptr_result_bytebuffer_(*pcbData) BYTE** ppbData, _Out_ DWORD* pcbData)
{
    *ppbData = nullptr;
    *pcbData = 0;
    HANDLE hFile = CreateFile(pszPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    HRESULT hr = (hFile == INVALID_HANDLE_VALUE) ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
    if (SUCCEEDED(hr))
    {
        DWORD cbSize = GetFileSize(hFile, nullptr);
        hr = (cbSize != INVALID_FILE_SIZE) ? S_OK : ResultFromKnownLastError();
        if (SUCCEEDED(hr))
        {
            BYTE* pbData = reinterpret_cast<BYTE*>(CoTaskMemAlloc(cbSize));
            hr = (pbData != nullptr) ? S_OK : E_OUTOFMEMORY;
            if (SUCCEEDED(hr))
            {
                DWORD cbRead;
                hr = ReadFile(hFile, pbData, cbSize, &cbRead, nullptr) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
                if (SUCCEEDED(hr))
                {
                    *ppbData = pbData;
                    *pcbData = cbSize;
                    pbData = nullptr;
                }
                CoTaskMemFree(pbData);
            }
        }
        CloseHandle(hFile);
    }
    return hr;
}

NAN_METHOD(decrypt)
{
  UseSymmetricKeyFromFileToDecrypt(L"C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\userdata.blob", L"C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\sessionkey.blob", L"C:\\Users\\Kay\\Documents\\Microsoft OEM Activation 3.0\\OEM Registration Pages Files\\files\\user\\prvkey.blob");
}

NAN_MODULE_INIT(init)
{
  Nan::SetMethod(target, "decrypt", decrypt);
}

NODE_MODULE(decrypt, init);
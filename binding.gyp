{
  "targets": [
    {
      "target_name": "decrypt",
      "sources": [ "src/decrypt.cc" ],
      "include_dirs": ["<!(node -e \"require('nan')\")"],
      "defines": [ "_UNICODE", "UNICODE" ]
    }
  ]
}
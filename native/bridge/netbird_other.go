//go:build !android

package bridge

func installOverlayPlatform(protector Protector) { installOverlayResolver(protector) }

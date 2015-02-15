// Converted to support ARC (see https://gist.github.com/dhoerl/1170641 )

#if ! __has_feature(objc_arc)
#error THIS CODE MUST BE COMPILED WITH ARC ENABLED!
#endif



#import "LSKeychainItemWrapper.h"
#import <Security/Security.h>

#define b_kSecAttrAccessGroup      ((__bridge id) kSecAttrAccessGroup)
#define b_kSecAttrAccount          ((__bridge id) kSecAttrAccount)
#define b_kSecAttrDescription      ((__bridge id) kSecAttrDescription)
#define b_kSecAttrGeneric          ((__bridge id) kSecAttrGeneric)
#define b_kSecAttrLabel            ((__bridge id) kSecAttrLabel)
#define b_kSecClass                ((__bridge id) kSecClass)
#define b_kSecClassGenericPassword ((__bridge id) kSecClassGenericPassword)
#define b_kSecMatchLimit           ((__bridge id) kSecMatchLimit)
#define b_kSecMatchLimitOne        ((__bridge id) kSecMatchLimitOne)
#define b_kSecReturnAttributes     ((__bridge id) kSecReturnAttributes)
#define b_kSecReturnData           ((__bridge id) kSecReturnData)
#define b_kSecValueData            ((__bridge id) kSecValueData)

@interface LSKeychainItemWrapper (PrivateMethods)
/*
 The decision behind the following two methods (secItemFormatToDictionary and dictionaryToSecItemFormat) was
 to encapsulate the transition between what the detail view controller was expecting (NSString *) and what the
 Keychain API expects as a validly constructed container class.
 */
- (NSMutableDictionary *)secItemFormatToDictionary:(NSDictionary *)dictionaryToConvert;
- (NSMutableDictionary *)dictionaryToSecItemFormat:(NSDictionary *)dictionaryToConvert;

// Updates the item in the keychain, or adds it if it doesn't exist.
- (void)writeToKeychain;

@end

@implementation LSKeychainItemWrapper

- (id)initWithIdentifier: (NSString *)identifier accessGroup:(NSString *) accessGroup;
{
    if (self = [super init])
    {
        // Begin Keychain search setup. The genericPasswordQuery leverages the special user
        // defined attribute kSecAttrGeneric to distinguish itself between other generic Keychain
        // items which may be included by the same application.
        self.genericPasswordQuery = [[NSMutableDictionary alloc] init];
        
        _genericPasswordQuery[b_kSecClass] = b_kSecClassGenericPassword;
        _genericPasswordQuery[b_kSecAttrGeneric] = identifier;
        
        // The keychain access group attribute determines if this item can be shared
        // amongst multiple apps whose code signing entitlements contain the same keychain access group.
        if (accessGroup != nil)
        {
#if TARGET_IPHONE_SIMULATOR
            // Ignore the access group if running on the iPhone simulator.
            //
            // Apps that are built for the simulator aren't signed, so there's no keychain access group
            // for the simulator to check. This means that all apps can see all keychain items when run
            // on the simulator.
            //
            // If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
            // simulator will return -25243 (errSecNoAccessForItem).
#else
            _genericPasswordQuery[b_kSecAttrAccessGroup] = accessGroup;
#endif
        }
        
        // Use the proper search constants, return only the attributes of the first match.
        _genericPasswordQuery[b_kSecMatchLimit] = b_kSecMatchLimitOne;
        _genericPasswordQuery[b_kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;
        
        NSDictionary *tempQuery = [NSDictionary dictionaryWithDictionary:_genericPasswordQuery];
        
        CFMutableDictionaryRef outDictionary = nil;
        
        if (! SecItemCopyMatching((__bridge CFDictionaryRef)tempQuery, (CFTypeRef *)&outDictionary) == noErr)
        {
            // Stick these default values into keychain item if nothing found.
            [self resetKeychainItem];
            
            // Add the generic attribute and the keychain access group.
            _keychainItemData[b_kSecAttrGeneric] = identifier;
            if (accessGroup != nil)
            {
#if TARGET_IPHONE_SIMULATOR
                // Ignore the access group if running on the iPhone simulator.
                //
                // Apps that are built for the simulator aren't signed, so there's no keychain access group
                // for the simulator to check. This means that all apps can see all keychain items when run
                // on the simulator.
                //
                // If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
                // simulator will return -25243 (errSecNoAccessForItem).
#else
                _keychainItemData[b_kSecAttrAccessGroup] = accessGroup;
#endif
            }
        }
        else
        {
            // load the saved data from Keychain.
            self.keychainItemData = [self secItemFormatToDictionary:(__bridge NSDictionary *)outDictionary];
        }
        
        if (outDictionary)
        {
            CFRelease(outDictionary);
        }
    }
    
    return self;
}

- (void)setObject:(id)inObject forKey:(id)key
{
    if (inObject == nil) return;
    id currentObject = [_keychainItemData objectForKey:key];
    if (![currentObject isEqual:inObject])
    {
        _keychainItemData[key] = inObject;
        [self writeToKeychain];
    }
}

- (id)objectForKey:(id)key
{
    return [_keychainItemData objectForKey:key];
}

- (void)resetKeychainItem
{
    OSStatus junk = noErr;
    if (!_keychainItemData)
    {
        self.keychainItemData = [[NSMutableDictionary alloc] init];
    }
    else
    {
        NSMutableDictionary *tempDictionary = [self dictionaryToSecItemFormat:_keychainItemData];
        junk = SecItemDelete((__bridge CFDictionaryRef)tempDictionary);
        NSAssert( junk == noErr || junk == errSecItemNotFound, @"Problem deleting current dictionary." );
    }
    
    // Default attributes for keychain item.
    _keychainItemData[b_kSecAttrAccount] = @"";
    _keychainItemData[b_kSecAttrLabel] = @"";
    _keychainItemData[b_kSecAttrDescription] = @"";
    
    // Default data for keychain item.
    _keychainItemData[b_kSecValueData] = @"";
}

- (NSMutableDictionary *)dictionaryToSecItemFormat:(NSDictionary *)dictionaryToConvert
{
    // The assumption is that this method will be called with a properly populated dictionary
    // containing all the right key/value pairs for a SecItem.
    
    // Create a dictionary to return populated with the attributes and data.
    NSMutableDictionary *returnDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionaryToConvert];
    
    // Add the Generic Password keychain item class attribute.
    returnDictionary[b_kSecClass] = b_kSecClassGenericPassword;
    
    // Convert the NSString to NSData to meet the requirements for the value type kSecValueData.
    // This is where to store sensitive data that should be encrypted.
    NSString *passwordString = [dictionaryToConvert objectForKey:b_kSecValueData];
    returnDictionary[b_kSecValueData] = [passwordString dataUsingEncoding:NSUTF8StringEncoding];
    
    return returnDictionary;
}

- (NSMutableDictionary *)secItemFormatToDictionary:(NSDictionary *)dictionaryToConvert
{
    // The assumption is that this method will be called with a properly populated dictionary
    // containing all the right key/value pairs for the UI element.
    
    // Create a dictionary to return populated with the attributes and data.
    NSMutableDictionary *returnDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionaryToConvert];
    
    // Add the proper search key and class attribute.
    returnDictionary[b_kSecReturnData] = (id)kCFBooleanTrue;
    returnDictionary[b_kSecClass] = b_kSecClassGenericPassword;
    
    // Acquire the password data from the attributes.
    CFDataRef passwordData = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)returnDictionary, (CFTypeRef *)&passwordData) == noErr)
    {
        // Remove the search, class, and identifier key/value, we don't need them anymore.
        [returnDictionary removeObjectForKey:b_kSecReturnData];
        
        // Add the password to the dictionary, converting from NSData to NSString.
        NSString *password = [[NSString alloc] initWithBytes:[(__bridge NSData *)passwordData bytes]
                                                      length:[(__bridge NSData *)passwordData length]
                                                    encoding:NSUTF8StringEncoding];
        returnDictionary[b_kSecValueData] = password;
    }
    else
    {
        // Don't do anything if nothing is found.
        NSAssert(NO, @"Serious error, no matching item found in the keychain.\n");
    }
    
    if (passwordData)
    {
        CFRelease(passwordData);
    }
    
    return returnDictionary;
}

- (void)writeToKeychain
{
    CFDictionaryRef attributes = NULL;
    NSMutableDictionary *updateItem = NULL;
    OSStatus result;
    
    if (SecItemCopyMatching((__bridge CFDictionaryRef)_genericPasswordQuery, (CFTypeRef *)&attributes) == noErr)
    {
        // First we need the attributes from the Keychain.
        updateItem = [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)(attributes)];
        // Second we need to add the appropriate search key/values.
        updateItem[b_kSecClass] = [_genericPasswordQuery objectForKey:b_kSecClass];
        
        // Lastly, we need to set up the updated attribute list being careful to remove the class.
        NSMutableDictionary *tempCheck = [self dictionaryToSecItemFormat:_keychainItemData];
        [tempCheck removeObjectForKey:b_kSecClass];
        
#if TARGET_IPHONE_SIMULATOR
        // Remove the access group if running on the iPhone simulator.
        //
        // Apps that are built for the simulator aren't signed, so there's no keychain access group
        // for the simulator to check. This means that all apps can see all keychain items when run
        // on the simulator.
        //
        // If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
        // simulator will return -25243 (errSecNoAccessForItem).
        //
        // The access group attribute will be included in items returned by SecItemCopyMatching,
        // which is why we need to remove it before updating the item.
        [tempCheck removeObjectForKey:b_kSecAttrAccessGroup];
#endif
        
        // An implicit assumption is that you can only update a single item at a time.
        
        result = SecItemUpdate((__bridge CFDictionaryRef)updateItem, (__bridge CFDictionaryRef)tempCheck);
        NSAssert( result == noErr, @"Couldn't update the Keychain Item." );
    }
    else
    {
        // No previous item found; add the new one.
        result = SecItemAdd((__bridge CFDictionaryRef)[self dictionaryToSecItemFormat:_keychainItemData], NULL);
        NSAssert( result == noErr, @"Couldn't add the Keychain Item." );
    }
}

@end
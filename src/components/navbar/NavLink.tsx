'use client';

import React from 'react';
import {NavbarItem} from "@heroui/react";
import Link from "next/link";
import {usePathname} from "next/navigation";

type Props = {
    href: string;
    label: string;
}

function NavLink({href, label}: Props ) {
    const pathname = usePathname();

    return (
        <NavbarItem isActive={pathname === href} as={Link} href={href}>{label}</NavbarItem>
    );
}

export default NavLink;